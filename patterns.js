const patterns = [

{
    name: "Email",
    label: "[EMAIL]",
    severity: "warning",
    penalty: 5,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
},

{
    name: "Phone Number",
    label: "[PHONE]",
    severity: "warning",
    penalty: 5,
    regex: /\b(?:\+?\d{1,3}[- ]?)?[6-9]\d{9}\b/g
},

{
    name: "URL",
    label: "[URL]",
    severity: "warning",
    penalty: 2,
    regex: /\bhttps?:\/\/[^\s]+\b/gi
},
{
    name: "Environment Secret",
    regex: /\b[A-Z][A-Z0-9_]{2,}\s*=\s*[^\s]+/g,
    label: "[ENV_SECRET]",
    severity: "critical",
    penalty: 25
},

{
    name: "Password",
    label: "[PASSWORD]",
    severity: "critical",
    penalty: 30,
    regex: /\b(password|pwd|passwd)\s*[:=]\s*([^\s]+)/gi
},

{
    name: "JWT Token",
    label: "[JWT]",
    severity: "critical",
    penalty: 40,
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
},

{
    name: "OpenAI API Key",
    label: "[OPENAI_KEY]",
    severity: "critical",
    penalty: 50,
    regex: /\bsk-[A-Za-z0-9_-]{20,}\b/g
},

{
    name: "GitHub Token",
    label: "[GITHUB_TOKEN]",
    severity: "critical",
    penalty: 50,
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g
},

{
    name: "AWS Access Key",
    label: "[AWS_KEY]",
    severity: "critical",
    penalty: 50,
    regex: /\bAKIA[0-9A-Z]{16}\b/g
},

{
    name: "Credit Card",
    regex: /\b(?:\d[ -]?){13,19}\d\b/g,
    label: "[CREDIT_CARD]",
    severity: "critical",
    penalty: 25
},

{
    name: "IPv4",
    label: "[IP]",
    severity: "info",
    penalty: 3,
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
},

{
    name: "UUID",
    label: "[UUID]",
    severity: "info",
    penalty: 2,
    regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi
},


];