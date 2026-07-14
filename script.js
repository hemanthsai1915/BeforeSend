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
const ignoredWords = [

    "function",
    "const",
    "let",
    "var",
    "return",
    "document",
    "window",
    "textarea",
    "scrollheight",
    "style",
    "height",
    "width",
    "padding",
    "margin"

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
        const value = match[0];
        if(pattern.name === "Credit Card"){

   const digits = value.replace(/\D/g, "");

    if(!isValidCreditCard(digits))
        return;

}
if(

findings.some(f=>

f.value === (match[2] || match[0])

)

){

return;

}

        findings.push({

            type:pattern.name,

            value:match[2] || match[0],

            label:pattern.label,

            severity:pattern.severity,

            penalty:pattern.penalty

        });

    });

});

   

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
    findings.push({

                type: pattern.name,

                value: value,

                label: pattern.label,

                severity: pattern.severity,

                penalty: pattern.penalty,

                regex: pattern.regex

            });

        });

    });
    const words = text.match(/[A-Za-z0-9!@#$%^&*()_+=\-]{12,}/g) || [];


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
        score>=3 &&
digits+symbols>=2 
    ){

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

    const key=item.type+"-"+item.value;

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

    

  let values="";

        items.forEach(item=>{

       values += `
<div class="findingRow">

<span class="findingValue">
${mask(item.value)}
</span>

<button
type="button"
class="toggleReveal material-symbols-rounded"
data-value="${item.value}"
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

    score -= Number(item.penalty || 0);

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

        setBanner(
            "danger",
            "Unsafe to Share"
        );

        break;

    case "warning":

        privacyScore.style.color="#f59e0b";

        riskLevel.textContent="Medium";

        riskLevel.style.color="#f59e0b";

        setBanner(
            "warning",
            "Review Before Sharing"
        );

        break;

    default:

        privacyScore.style.color="#22c55e";

        riskLevel.textContent="Low";

        riskLevel.style.color="#22c55e";

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

   const counts = {};

findings.forEach(item=>{

    counts[item.type] =
        (counts[item.type] || 0) + 1;

});

let html = "";

html += `Detected ${Object.keys(counts).length} categories.<br><br>`;

Object.entries(counts).forEach(([type,count])=>{

    html += `• ${type} (${count})<br>`;

});

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

    text = text.replaceAll(

        item.value,

        item.label || "[SECRET]"

    );

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