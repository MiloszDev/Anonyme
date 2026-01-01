import sys
import json
import argparse
from typing import List, Dict

from anonyme.analyze import analyze


__version__ = "1.0.0"


class CLIFormatter:
    
    COLORS = {
        'ALLOW': '\033[92m',
        'BLOCK': '\033[91m',
        'REDACT': '\033[93m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
    }
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        if color in cls.COLORS:
            return f"{cls.COLORS[color]}{text}{cls.COLORS['RESET']}"
        return text
    
    @classmethod
    def action_badge(cls, action: str) -> str:
        badges = {
            'ALLOW': f"{cls.COLORS['ALLOW']}ALLOW{cls.COLORS['RESET']}",
            'BLOCK': f"{cls.COLORS['BLOCK']}BLOCK{cls.COLORS['RESET']}",
            'REDACT': f"{cls.COLORS['REDACT']}REDACT{cls.COLORS['RESET']}",
        }
        return badges.get(action, action)


def print_banner():
    print()
    print("=" * 60)
    print(f"  {CLIFormatter.COLORS['BOLD']}Anonyme CLI{CLIFormatter.COLORS['RESET']} - v{__version__}")
    print("=" * 60)
    print()


def print_result(result, verbose: bool = False):
    print()
    print("-" * 60)
    
    action_display = CLIFormatter.action_badge(result.action)
    print(f"Action:      {action_display}")
    
    risk = result.risk_score
    risk_bar = "█" * int(risk * 10) + "░" * (10 - int(risk * 10))
    risk_color = 'ALLOW' if risk < 0.5 else 'REDACT' if risk < 0.8 else 'BLOCK'
    print(f"Risk Score:  {CLIFormatter.colorize(f'{risk:.2f}', risk_color)} [{risk_bar}]")
    
    if result.reasons:
        print(f"Findings:    {len(result.reasons)} issue(s) detected")
        if verbose:
            for idx, reason in enumerate(result.reasons, 1):
                print(f"  {idx}. {reason}")
    else:
        print("Findings:    " + CLIFormatter.colorize("No issues detected", 'ALLOW'))
    
    if verbose and result.metadata:
        print("Metadata:")
        for key, value in result.metadata.items():
            print(f"  {key}: {value}")
    
    print("-" * 60)


def format_json_output(prompts: List[str], results: List) -> str:
    output = {
        "version": __version__,
        "total_prompts": len(prompts),
        "results": []
    }
    
    for prompt, result in zip(prompts, results):
        output["results"].append({
            "prompt": prompt,
            "action": result.action,
            "risk_score": result.risk_score,
            "reasons": result.reasons,
            "metadata": result.metadata
        })
    
    return json.dumps(output, indent=2)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='DataAnonymizator - Analyze prompts for security and privacy risks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m anonyme.interface.cli "What is Alice's SSN?"
  python -m anonyme.interface.cli "Hello" "Test prompt" --verbose
  python -m anonyme.interface.cli "Check this" --json
        """
    )
    
    parser.add_argument('prompts', nargs='+', help='One or more prompts to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--version', action='version', version=f'DataAnonymizator CLI v{__version__}')
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    if not args.json:
        print_banner()
    
    context: List[Dict[str, str]] = []
    results = []
    errors = []
    
    if not args.json:
        print(f"Analyzing {len(args.prompts)} prompt(s)\n")
    
    for i, prompt in enumerate(args.prompts, 1):
        if not args.json:
            print(f"[{i}/{len(args.prompts)}] {CLIFormatter.COLORS['DIM']}{prompt}{CLIFormatter.COLORS['RESET']}")
        
        try:
            result = analyze(prompt, context)
            results.append(result)
            
            if not args.json:
                print_result(result, verbose=args.verbose)
                
        except Exception as e:
            error_msg = f"Error analyzing prompt {i}: {str(e)}"
            errors.append(error_msg)
            if not args.json:
                print(f"{CLIFormatter.colorize(error_msg, 'BLOCK')}\n")
    
    if args.json:
        print(format_json_output(args.prompts, results))
    else:
        print()
        print("=" * 60)
        total = len(args.prompts)
        success = len(results)
        failed = len(errors)
        
        print(f"Summary: {success}/{total} analyzed successfully")
        if failed > 0:
            print(f"Failed:  {failed}")
        
        if results:
            action_counts = {}
            for r in results:
                action_counts[r.action] = action_counts.get(r.action, 0) + 1
            
            print("\nActions:")
            for action, count in sorted(action_counts.items()):
                badge = CLIFormatter.action_badge(action)
                print(f"  {badge}: {count}")
        
        print("=" * 60)
        print(f"{CLIFormatter.colorize('Analysis complete', 'ALLOW')}\n")
    
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
