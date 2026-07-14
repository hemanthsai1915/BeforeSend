const textarea = document.getElementById("inputText");
const resultsList = document.getElementById("resultsList");

const privacyScore = document.getElementById("privacyScore");
const issueCount = document.getElementById("issueCount");
const wordCount = document.getElementById("wordCount");
const charCount = document.getElementById("charCount");

const statusBanner = document.getElementById("statusBanner");

const redactBtn = document.getElementById("redactBtn");
const copyBtn = document.getElementById("copyBtn");
const clearBtn = document.getElementById("clearBtn");
const ignoredWords=[
"function",
"return",
"const",
"let",
"var",
"width",
"height",
"display",
"padding",
"margin",
"background",
"color",
"border",
"style",
"document",
"window",
"textarea",
"onclick",
"scrollheight",
"overflow",
"hidden",
"visible",
"button",
"class",
"html",
"body",
"script",
"input",
"value",
"textcontent"
];
textarea.addEventListener("input", () => {

    autoResize();

    scan();
    

});


redactBtn.onclick = redactAll;
copyBtn.onclick = copyText;
clearBtn.onclick = clearAll;

scan();

function scan(){
updateButtons();
    updateStats();

    const text = textarea.value.trim();

    if(text===""){
autoResize();
        resultsList.innerHTML =
        "<li class='safe'>Paste text to begin scanning.</li>";

        issueCount.textContent = "0";
       privacyScore.textContent = "Not Scanned";
       
riskLevel.textContent="Not Scanned";

riskLevel.style.color="#94a3b8";
        privacyScore.style.color="#22c55e";

       setBanner(
    "ready",
    "Ready to Scan"
);
document.getElementById("summaryText").textContent =
"Paste text to start scanning.";
textarea.style.borderColor = "#3b82f6";
textarea.style.boxShadow = "0 0 12px rgba(59,130,246,.25)";
        return;

    }

    const findings = findMatches(text);

    renderResults(findings);

    updateScore(findings);

}
function findMatches(text){

const findings = [];

// Context-aware detection
contextPatterns.forEach(pattern=>{

    const matches = [...text.matchAll(pattern.regex)];

    matches.forEach(match=>{
    const value = (match[2] || match[0]).trim();

let type = pattern.name;

const t = type.toLowerCase();

if (["password","pass","passwd","pwd","pin"].includes(t))
    type = "Password";
else if (t.includes("api"))
    type = "API Key";
else if (t.includes("token"))
    type = "Token";
else if (t.includes("secret"))
    type = "Secret";
if (
    findings.some(f =>
        f.type === type &&
        f.value === value
    )
)
    return;

        findings.push({

            type,
            value,
            label:pattern.label,

            severity:pattern.severity,

            penalty:pattern.penalty

        });

    });

});

   const genericContext =
/\b(password|passwd|pass|pwd|pin|secret|private[_-]?key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|bearer|jwt|session|cookie|db[_-]?password|database[_-]?url|connection[_-]?string)\b\s*[:=]\s*([^\s"'`;]+)/gi;

for(const match of text.matchAll(genericContext)){

    const value = match[2];
    const key = match[1].toLowerCase();

let type = key;

if(["password","pass","passwd","pwd","pin"].includes(key)){
    type = "Password";
}
else if(key.includes("api")){
    type = "API Key";
}
else if(key.includes("token")){
    type = "Token";
}
else if(key.includes("secret")){
    type = "Secret";
}

    if(value.length < 4)
        continue;
if(
    findings.some(f =>
        f.type === type &&
        f.value === value
    )
){
    continue;
}
    findings.push({

        type,

        value,

        label: "[SECRET]",

        severity: "critical",

        penalty: 20

    });

}

    patterns.forEach(pattern=>{

       const matches = [...text.matchAll(pattern.regex)]; 

        if(!matches) return;

       matches.forEach(match=>{
const value = match[0];
    if(pattern.name==="Possible Secret"){

        const hasUpper = /[A-Z]/.test(value);
        const hasLower = /[a-z]/.test(value);
        const hasNumber = /\d/.test(value);
        const hasSymbol = /[^A-Za-z0-9]/.test(value);
      

        const score =
            Number(hasUpper) +
            Number(hasLower) +
            Number(hasNumber) +
            Number(hasSymbol);

        if(score < 3){
            return;
        }
    }
if(
    ignoredWords.includes(
        value.toLowerCase()
    )
){
    return;
}
if(findings.some(f=>f.value===value))
    return;

  let type = pattern.name;

if (["password","pass","passwd","pwd","pin"].includes(type.toLowerCase()))
    type = "Password";

if (type.toLowerCase().includes("api"))
    type = "API Key";

if (type.toLowerCase().includes("token"))
    type = "Token";

if (type.toLowerCase().includes("secret"))
    type = "Secret";

findings.push({
                type,

                value: value,

                label: pattern.label,

                severity: pattern.severity,

                penalty: pattern.penalty,

                regex: pattern.regex

            });

        });

    });
   const words=text.match(/[A-Za-z0-9_\-+=\/!@#$%^&*]{16,}/g)||[];


words.forEach(word => {
    if(
    /^[.#]/.test(word) ||
    word.includes("{") ||
    word.includes("}") ||
    word.includes(":") ||
    word.includes(";") ||
    word.includes("(") ||
    word.includes(")")
){
    return;
}

    const hasUpper = /[A-Z]/.test(word);
    const hasLower = /[a-z]/.test(word);
    const hasNumber = /\d/.test(word);
    const hasSymbol = /[^A-Za-z0-9]/.test(word);
      const digits=(word.match(/\d/g)||[]).length;

const symbols=(word.match(/[^A-Za-z0-9]/g)||[]).length;
if(
    ignoredWords.includes(
        word.toLowerCase()
    )
){
    return;
}
    const score =
        Number(hasUpper) +
        Number(hasLower) +
        Number(hasNumber) +
        Number(hasSymbol);

   const alreadyDetected = findings.some(f =>

    f.value === word ||

    word.includes(f.value)

);

if(
    !alreadyDetected &&
    word.length >= 12 &&
       score===4 &&
word.length>=20 &&
digits>=3 &&
symbols>=2
    ){
if(findings.some(f=>f.value===word)){
    return;
}
        findings.push({

            type:"Possible Secret",

            value:word,

            label:"[SECRET]",

            severity:"critical",

            penalty:20

        });

    }

});
    const unique=[];

const seen=new Set();

findings.forEach(item=>{

  const key =
    item.type.toLowerCase() +
    "|" +
    item.value.toLowerCase();

    if(!seen.has(key)){

        seen.add(key);

        unique.push(item);

    }

});

return unique;

}

function renderResults(findings){

    resultsList.innerHTML = "";

    if(findings.length===0){

        resultsList.innerHTML =
        "<li class='safe'>No sensitive information detected.</li>";

        return;

    }

    const grouped = {};

    findings.forEach(item=>{

        if(!grouped[item.type]){

            grouped[item.type]=[];

        }

        grouped[item.type].push(item);

    });

    Object.entries(grouped).forEach(([type, items]) => {

    const li = document.createElement("li");

    const severity = items[0].severity;

    li.style.borderLeftColor =
        severity === "critical"
            ? "#ef4444"
        : severity === "warning"
            ? "#f59e0b"
            : "#3b82f6";

    

 let values = "";

const uniqueValues = [...new Set(items.map(i => i.value))];

uniqueValues.forEach(value => {

    values += `
<div class="findingRow">

<span class="findingValue">
${mask(value)}
</span>

<button
type="button"
class="toggleReveal material-symbols-rounded"
data-value="${value}"
data-state="hidden">
visibility
</button>

</div>
`;

});

        li.innerHTML=`

            
<div class="title">

   <strong>${type} (${items.length})</strong>

   
   

</div>

${values}
`;

        

        resultsList.appendChild(li);

   

});

}
function updateScore(findings){

    let score = 100;
    const severityOrder = {
    info: 0,
    warning: 1,
    critical: 2
};

const highestSeverity = findings.reduce(

    (highest,item)=>{

        return severityOrder[item.severity] >
               severityOrder[highest]
            ? item.severity
            : highest;

    },

    "info"

);

   findings.forEach(item => {

    console.log(item.type, item.penalty);

    score=Math.max(0,score-Number(item.penalty||0));

});



    if(score < 0)
        score = 0;

    privacyScore.innerHTML =
`${score}<small>/100</small>`;

  switch(highestSeverity){

    case "critical":

        privacyScore.style.color="#ef4444";

        riskLevel.textContent="High";

        riskLevel.style.color="#ef4444";
        textarea.style.borderColor="#ef4444";
textarea.style.boxShadow="0 0 20px rgba(239,68,68,.35)";

        setBanner(
            "danger",
            "Unsafe to Share"
        );

        break;

    case "warning":

        privacyScore.style.color="#f59e0b";

        riskLevel.textContent="Medium";

        riskLevel.style.color="#f59e0b";
        textarea.style.borderColor="#f59e0b";
textarea.style.boxShadow="0 0 16px rgba(245,158,11,.25)";

        setBanner(
            "warning",
            "Review Before Sharing"
        );

        break;

    default:

        privacyScore.style.color="#22c55e";

        riskLevel.textContent="Low";

        riskLevel.style.color="#22c55e";
        textarea.style.borderColor="#22c55e";
textarea.style.boxShadow="0 0 14px rgba(34,197,94,.2)";

        setBanner(
            "safe",
            "Safe to Share"
        );

}

    issueCount.textContent = findings.length;
const summary = document.getElementById("summaryText");

if(findings.length===0){

    summary.innerHTML = `
        No sensitive information detected.
    `;

}
else{

   const highest = findings.some(f=>f.severity==="critical")
    ? "Critical"
    : findings.some(f=>f.severity==="warning")
        ? "Warning"
        : "Info";

let html = `
<b>${findings.length} sensitive item(s) detected.</b><br><br>

Highest Risk:
<b>${highest}</b><br><br>

Recommendation:<br>
• Use <b>Redact All</b> before sharing.
`;
if(findings.some(f=>f.type==="Password")){
    html += "<br>• Passwords should never be shared.";
}

if(findings.some(f=>f.type==="API Key")){
    html += "<br>• Revoke exposed API keys.";
}

if(findings.some(f=>f.type==="Bearer Token")){
    html += "<br>• Tokens should be regenerated.";
}

if(findings.some(f=>f.type==="Credit Card")){
    html += "<br>• Remove payment card details.";
}

if(findings.some(f=>f.type==="Email")){
    html += "<br>• Remove unnecessary personal emails.";
}

summary.innerHTML = html;
}

}

function setBanner(type,text){

    statusBanner.className = "status " + type;

    statusBanner.textContent = text;

}

function updateStats(){

    const text = textarea.value;

    charCount.textContent = text.length;
   

    const words = text.trim()
        ? text.trim().split(/\s+/).length
        : 0;

    wordCount.textContent = words;

}

function mask(value){

    if(value.includes("@")){

        const parts = value.split("@");

        return parts[0].substring(0,2)
            + "****@"
            + parts[1];

    }

    if(/^\d{10}$/.test(value)){

        return value.substring(0,2)
            + "******"
            + value.substring(8);

    }
    if(value.startsWith("sk-"))
    return value.substring(0,6)+"****************";

if(value.startsWith("ghp_"))
    return value.substring(0,8)+"****************";

if(value.startsWith("AKIA"))
    return value.substring(0,4)+"************";

    if(value.length <= 8){

        return "*".repeat(value.length);

    }

    const keep=Math.min(3,Math.floor(value.length/4));

return (
    value.substring(0, keep) +
    "*".repeat(value.length - keep * 2) +
    value.substring(value.length - keep)
);

}
function isValidCreditCard(number){

    number = number.replace(/\D/g, "");

    if(number.length < 13 || number.length > 19)
        return false;

    let sum = 0;
    let shouldDouble = false;

    for(let i = number.length - 1; i >= 0; i--){

        let digit = Number(number[i]);

        if(Number.isNaN(digit))
            return false;

        if(shouldDouble){

            digit *= 2;

            if(digit > 9)
                digit -= 9;

        }

        sum += digit;
        shouldDouble = !shouldDouble;

    }

    return sum % 10 === 0;

}
function redactAll(){

    if(textarea.value.trim()===""){

        showToast("Nothing to redact.");

        return;

    }

    let text = textarea.value;

  const findings = findMatches(text);

findings.forEach(item=>{

    text = text.split(item.value).join(item.label);

});
    

    textarea.value = text;

    autoResize();

    scan();

    showToast("Sensitive data redacted");

}

async function copyText(){

    if(textarea.value.trim()===""){

        showToast("Nothing to copy.");

        return;

    }

    try{

        await navigator.clipboard.writeText(textarea.value);

        showToast("Copied");

    }
    catch{

        showToast("Copy failed");

    }

}
function updateButtons(){

    const hasText = textarea.value.trim() !== "";

    redactBtn.disabled = !hasText;

    copyBtn.disabled = !hasText;

}

function clearAll(){

    textarea.value = "";
    ocrCount = 0;

    autoResize();

    scan();

    textarea.focus();

}

function showToast(message){

    let toast=document.getElementById("toast");

    if(!toast){

        toast=document.createElement("div");

        toast.id="toast";

        document.body.appendChild(toast);

    }

    toast.textContent=message;

    toast.classList.add("show");

    clearTimeout(window.toastTimer);

    window.toastTimer=setTimeout(()=>{

        toast.classList.remove("show");

    },2200);

}
function autoResize(){

    textarea.style.height = "auto";

    const maxHeight = 320;

    textarea.style.height =
        Math.min(textarea.scrollHeight, maxHeight) + "px";

    textarea.style.overflowY =
        textarea.scrollHeight > maxHeight
            ? "auto"
            : "hidden";

}
document.addEventListener("click",(e)=>{

   const eye = e.target.closest(".toggleReveal");

if(!eye)
    return;

    const value =
        eye.previousElementSibling;

    if(eye.dataset.state==="hidden"){

        value.textContent =
            eye.dataset.value;

eye.textContent = "visibility_off";

        eye.dataset.state="shown";

    }
    else{

        value.textContent =
            mask(eye.dataset.value);
eye.textContent = "visibility";

        eye.dataset.state="hidden";

    }

});

// Auto Type Detector

document.addEventListener("keydown", (e) => {

    // Ignore shortcuts
    if (e.ctrlKey || e.metaKey || e.altKey)
        return;

    // Already typing in the textarea
    if (document.activeElement === textarea)
        return;

    // Ignore function/navigation keys
    if (e.key.length !== 1)
        return;

    // Ignore typing in another input
    const tag = document.activeElement.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA")
        return;

    e.preventDefault();

    textarea.focus();

    textarea.value += e.key;

    autoResize();
    scan();

});


//paste text or images using ctrl+v
document.addEventListener("paste", (e)=>{

    const items = e.clipboardData.items;

    for(const item of items){

        if(item.type.startsWith("image/")){

            const file = item.getAsFile();

            runOCR(file);

            return;

        }

    }

    const text = e.clipboardData.getData("text");

    if(!text)
        return;

    if(document.activeElement !== textarea){

        e.preventDefault();

        textarea.focus();

    }

    textarea.value +=
        textarea.value
            ? "\n"+text
            : text;

    autoResize();

    scan();

});


//drag and drop text
document.addEventListener("dragover", (e) => {

    e.preventDefault();

    textarea.classList.add("dragActive");

});

document.addEventListener("drop", () => {

    textarea.classList.remove("dragActive");

});

document.addEventListener("dragend", () => {

    textarea.classList.remove("dragActive");

});

document.addEventListener("drop", async (e) => {

    e.preventDefault();

    textarea.classList.remove("dragActive");

    const items = e.dataTransfer.items;

    if (!items || items.length === 0)
        return;

    // ---------- Image ----------
    const imageItem = [...items].find(item =>
        item.kind === "file" &&
        item.type.startsWith("image/")
    );

    if (imageItem) {

        const file = imageItem.getAsFile();

        runOCR(file);

        return;

    }

    // ---------- Text ----------
    const text = e.dataTransfer.getData("text");

    if (text) {

        textarea.value +=
            textarea.value ? "\n" + text : text;

        autoResize();

        scan();

        textarea.focus();

    }

});

let ocrCount = 0;
async function runOCR(file){

    if(!file)
        return;

    imageBtn.disabled = true;

    imageBtn.innerHTML = `
        <span class="material-symbols-rounded spinner">
            autorenew
        </span>

        <span id="ocrStatus">
            Starting...
        </span>
    `;

    showToast("Extracting text from image...");

    try{

        const result = await Tesseract.recognize(
    file,
    "eng",
    {
       logger: (m) => {

    const status = document.getElementById("ocrStatus");

    if (!status)
        return;

    status.textContent =
        `${m.status} ${Math.round((m.progress || 0) * 100)}%`;

}
    }
);

        const text = result.data.text.trim();

        if(!text){

            showToast(
    "No readable text found in the image."
);

        }else{

          textarea.value +=
    (textarea.value ? "\n\n" : "") +
    `──────── OCR Result ${++ocrCount} ────────\n` +
    text;


            autoResize();
            scan();
            textarea.scrollTop = textarea.scrollHeight;
textarea.focus();
            showToast(
    `OCR completed • ${text.length} characters extracted`
);

        }

    }catch(err){

        console.error(err);

        showToast("OCR failed.");

    }finally{

        imageBtn.disabled = false;

        imageBtn.innerHTML = `
            <span class="material-symbols-rounded">
                image_search
            </span>
            OCR Scan
        `;

        imageInput.value = "";

    }


}

//upload image scan text in it
imageBtn.onclick = () => imageInput.click();

imageInput.onchange = (e)=>{

    const file = e.target.files[0];

    if(file)
        runOCR(file);

};