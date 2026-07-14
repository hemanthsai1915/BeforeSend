const contextPatterns = [

{
    name:"Password",
    regex:/\b(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)/gi
},

{
    name:"API Key",
    regex:/\b(api[_-]?key)\s*[:=]\s*([^\s,;]+)/gi
},

{
    name:"Token",
    regex:/\b(token|access[_-]?token)\s*[:=]\s*([^\s,;]+)/gi
},

{
    name:"Secret",
    regex:/\b(secret)\s*[:=]\s*([^\s,;]+)/gi
},

{
    name:"Bearer Token",
    regex:/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi
}

];