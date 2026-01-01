Input: User Message (e.g. "What is Alice’s SSN?"), string

Conversion state
```
[
  { role: "system", content: "You are a payroll assistant" },
  { role: "user", content: "Show me employee records" },
  { role: "assistant", content: "Which employee?" },
  { role: "user", content: "Alice" }
]
```, array of objects with role and content properties

System / Developer Instructions

RAG

Metadata
- User identity / role
- Permissions
- Data classification labels
- Time / jurisdiction / policy version

🔑 Important: Most “prompt firewalls” today only take (1).
A real one must take (1–5)

### Internal Representation

a. tokenized text
b. semantic embeddings
c. Entity Graphs
d. Conversation intent state

### Output: Anonymized Message


Core system operations
