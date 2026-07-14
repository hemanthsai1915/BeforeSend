const extraPatterns = [

{
    name:"GitHub Personal Access Token",
    regex:/\bghp_[A-Za-z0-9]{36}\b/g,
    label:"[GITHUB_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"GitHub Fine-grained Token",
    regex:/\bgithub_pat_[A-Za-z0-9_]{80,}\b/g,
    label:"[GITHUB_FINE_GRAINED]",
    severity:"critical",
    penalty:30
},

{
    name:"GitHub OAuth Token",
    regex:/\bgho_[A-Za-z0-9]{36}\b/g,
    label:"[GITHUB_OAUTH]",
    severity:"critical",
    penalty:30
},

{
    name:"GitHub App Token",
    regex:/\bghu_[A-Za-z0-9]{36}\b/g,
    label:"[GITHUB_APP]",
    severity:"critical",
    penalty:30
},

{
    name:"GitHub Refresh Token",
    regex:/\bghr_[A-Za-z0-9]{36}\b/g,
    label:"[GITHUB_REFRESH]",
    severity:"critical",
    penalty:30
},

{
    name:"AWS Access Key",
    regex:/\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
    label:"[AWS_ACCESS_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Google API Key",
    regex:/\bAIza[0-9A-Za-z\\-_]{35}\b/g,
    label:"[GOOGLE_API_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"OpenAI API Key",
    regex:/\bsk-proj-[A-Za-z0-9_-]{20,}\b/g,
    label:"[OPENAI_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"OpenAI Legacy Key",
    regex:/\bsk-[A-Za-z0-9]{32,}\b/g,
    label:"[OPENAI_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Anthropic API Key",
    regex:/\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b/g,
    label:"[ANTHROPIC_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Azure Client Secret",
    regex:/(?:^|[\s="'`])([A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_.~-]{31,34})(?=$|[\s"'`,])/g,
    label:"[AZURE_CLIENT_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"JWT",
    regex:/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    label:"[JWT]",
    severity:"warning",
    penalty:20
},

{
    name:"Bearer Token",
    regex:/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
    label:"[BEARER_TOKEN]",
    severity:"critical",
    penalty:25
},

{
    name:"Private Key",
    regex:/-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----[\s\S]+?-----END(?: RSA| EC| OPENSSH)? PRIVATE KEY-----/g,
    label:"[PRIVATE_KEY]",
    severity:"critical",
    penalty:35
},

{
    name:"Firebase URL",
    regex:/https:\/\/[A-Za-z0-9-]+\.firebaseio\.com/gi,
    label:"[FIREBASE]",
    severity:"warning",
    penalty:15
},

{
    name:"Slack Token",
    regex:/xox[baprs]-[A-Za-z0-9-]{20,}/g,
    label:"[SLACK_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Discord Bot Token",
    regex:/[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
    label:"[DISCORD_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Stripe Secret Key",
    regex:/\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    label:"[STRIPE_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Stripe Publishable Key",
    regex:/\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    label:"[STRIPE_PUBLIC]",
    severity:"warning",
    penalty:10
},

{
    name:"Twilio API Key",
    regex:/SK[a-fA-F0-9]{32}/g,
    label:"[TWILIO_KEY]",
    severity:"critical",
    penalty:30
}

];
const databasePatterns = [

{
    name:"PostgreSQL URI",
    regex:/postgres(?:ql)?:\/\/[^\s"'`]+/gi,
    label:"[POSTGRES_URI]",
    severity:"critical",
    penalty:30
},

{
    name:"MySQL URI",
    regex:/mysql:\/\/[^\s"'`]+/gi,
    label:"[MYSQL_URI]",
    severity:"critical",
    penalty:30
},

{
    name:"MongoDB URI",
    regex:/mongodb(?:\+srv)?:\/\/[^\s"'`]+/gi,
    label:"[MONGODB_URI]",
    severity:"critical",
    penalty:30
},

{
    name:"Redis URI",
    regex:/redis(?:s)?:\/\/[^\s"'`]+/gi,
    label:"[REDIS_URI]",
    severity:"critical",
    penalty:30
},

{
    name:"SQL Server Connection",
    regex:/Server=.*?Database=.*?(?:Password|Pwd)=.*?(?:;|$)/gi,
    label:"[SQLSERVER_CONNECTION]",
    severity:"critical",
    penalty:30
},

{
    name:"Azure Storage Connection",
    regex:/DefaultEndpointsProtocol=.*?AccountName=.*?AccountKey=.*?(?:;|$)/gi,
    label:"[AZURE_STORAGE_CONNECTION]",
    severity:"critical",
    penalty:30
},

{
    name:"Azure SAS Token",
    regex:/\?sv=[^"'`\s]+&sig=[^"'`\s]+/gi,
    label:"[AZURE_SAS_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"DATABASE_URL",
    regex:/DATABASE_URL\s*[:=]\s*["']?.+/gi,
    label:"[DATABASE_URL]",
    severity:"critical",
    penalty:25
},

{
    name:"DB_PASSWORD",
    regex:/DB_PASSWORD\s*[:=]\s*["']?([^"'\n\r]+)/gi,
    label:"[DB_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"POSTGRES_PASSWORD",
    regex:/POSTGRES_PASSWORD\s*[:=]\s*["']?.+/gi,
    label:"[POSTGRES_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"MYSQL_ROOT_PASSWORD",
    regex:/MYSQL_ROOT_PASSWORD\s*[:=]\s*["']?.+/gi,
    label:"[MYSQL_ROOT_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"MONGO_INITDB_ROOT_PASSWORD",
    regex:/MONGO_INITDB_ROOT_PASSWORD\s*[:=]\s*["']?.+/gi,
    label:"[MONGO_ROOT_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"Connection String",
    regex:/(?:connection|string|connstring)\s*[:=]\s*["']?.+/gi,
    label:"[CONNECTION_STRING]",
    severity:"critical",
    penalty:25
},

{
    name:"Host Password Pair",
    regex:/(?:host|server).{0,80}(?:password|pwd).{0,80}/gi,
    label:"[DATABASE_CREDENTIALS]",
    severity:"warning",
    penalty:20
},

{
    name:"Docker Secret ENV",
    regex:/(?:PASSWORD|TOKEN|SECRET|API_KEY)\s*=\s*["']?[^\s"']{8,}/g,
    label:"[ENV_SECRET]",
    severity:"critical",
    penalty:25
},

{
    name:".env Secret",
    regex:/^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z0-9_]*\s*=\s*.+$/gim,
    label:"[ENV_SECRET]",
    severity:"critical",
    penalty:25
},

{
    name:"Spring datasource password",
    regex:/spring\.datasource\.password\s*[:=]\s*.+/gi,
    label:"[SPRING_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"Redis Password",
    regex:/REDIS_PASSWORD\s*[:=]\s*.+/gi,
    label:"[REDIS_PASSWORD]",
    severity:"critical",
    penalty:25
},

{
    name:"Oracle JDBC",
    regex:/jdbc:oracle:[^\s"'`]+/gi,
    label:"[ORACLE_JDBC]",
    severity:"critical",
    penalty:25
},

{
    name:"PostgreSQL JDBC",
    regex:/jdbc:postgresql:[^\s"'`]+/gi,
    label:"[POSTGRES_JDBC]",
    severity:"critical",
    penalty:25
}

];
const cloudPatterns = [

{
    name:"GitLab Personal Access Token",
    regex:/\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    label:"[GITLAB_PAT]",
    severity:"critical",
    penalty:30
},

{
    name:"GitLab Runner Token",
    regex:/\bGR1348941[A-Za-z0-9_-]{20,}\b/g,
    label:"[GITLAB_RUNNER]",
    severity:"critical",
    penalty:30
},

{
    name:"GitHub Fine Grained Token",
    regex:/\bgithub_pat_[A-Za-z0-9_]{70,}\b/g,
    label:"[GITHUB_FINE]",
    severity:"critical",
    penalty:30
},

{
    name:"Docker Hub Token",
    regex:/\bdckr_pat_[A-Za-z0-9_-]{20,}\b/g,
    label:"[DOCKER_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Firebase Service Account",
    regex:/\"type\"\s*:\s*\"service_account\"/g,
    label:"[FIREBASE_SERVICE_ACCOUNT]",
    severity:"critical",
    penalty:30
},

{
    name:"Google Service Account",
    regex:/\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----/g,
    label:"[GOOGLE_SERVICE_ACCOUNT]",
    severity:"critical",
    penalty:35
},

{
    name:"Google OAuth Client Secret",
    regex:/\"client_secret\"\s*:\s*\"[^\"]+\"/g,
    label:"[GOOGLE_CLIENT_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Azure Tenant ID",
    regex:/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    label:"[AZURE_TENANT]",
    severity:"warning",
    penalty:10
},

{
    name:"Azure Storage Account Key",
    regex:/AccountKey=([A-Za-z0-9+/=]{40,})/gi,
    label:"[AZURE_STORAGE_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Azure Client ID",
    regex:/client[_-]?id\s*[:=]\s*[0-9a-f-]{36}/gi,
    label:"[AZURE_CLIENT_ID]",
    severity:"warning",
    penalty:10
},

{
    name:"AWS Secret Access Key",
    regex:/aws(.{0,20})?(secret|access).{0,20}[:=]\s*['"]?([A-Za-z0-9\/+=]{40})/gi,
    label:"[AWS_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"AWS Session Token",
    regex:/FwoG[A-Za-z0-9\/+=]{80,}/g,
    label:"[AWS_SESSION]",
    severity:"critical",
    penalty:30
},

{
    name:"Kubernetes Secret",
    regex:/kind:\s*Secret/gi,
    label:"[KUBERNETES_SECRET]",
    severity:"warning",
    penalty:15
},

{
    name:"KubeConfig",
    regex:/apiVersion:\s*v1[\s\S]{0,400}clusters:/gi,
    label:"[KUBECONFIG]",
    severity:"critical",
    penalty:25
},

{
    name:"GitHub Actions Secret",
    regex:/\${{\s*secrets\.[A-Za-z0-9_]+\s*}}/g,
    label:"[GITHUB_ACTION_SECRET]",
    severity:"warning",
    penalty:10
},

{
    name:"Terraform Variable Secret",
    regex:/variable\s+"[^"]+"\s*{[\s\S]{0,100}sensitive\s*=\s*true/gi,
    label:"[TERRAFORM_SECRET]",
    severity:"warning",
    penalty:10
},

{
    name:"Terraform AWS Key",
    regex:/access_key\s*=\s*"[^"]+"/gi,
    label:"[TF_AWS_KEY]",
    severity:"critical",
    penalty:25
},

{
    name:"Terraform Secret Key",
    regex:/secret_key\s*=\s*"[^"]+"/gi,
    label:"[TF_SECRET]",
    severity:"critical",
    penalty:25
},

{
    name:"Netlify Token",
    regex:/\bnfp_[A-Za-z0-9]{40,}\b/g,
    label:"[NETLIFY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Vercel Token",
    regex:/\bvercel_[A-Za-z0-9]{20,}\b/g,
    label:"[VERCEL_TOKEN]",
    severity:"critical",
    penalty:30
}

];
const servicePatterns = [

{
    name:"OpenRouter API Key",
    regex:/\bsk-or-v1-[A-Za-z0-9_-]{40,}\b/g,
    label:"[OPENROUTER_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Cohere API Key",
    regex:/\bco_[A-Za-z0-9]{38,}\b/g,
    label:"[COHERE_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Mistral API Key",
    regex:/\b[a-zA-Z0-9]{32,}\b(?=.*mistral)/gi,
    label:"[MISTRAL_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Hugging Face Token",
    regex:/\bhf_[A-Za-z0-9]{30,}\b/g,
    label:"[HF_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Replicate API Token",
    regex:/\br8_[A-Za-z0-9]{35,}\b/g,
    label:"[REPLICATE_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Pinecone API Key",
    regex:/\b[a-f0-9]{32}(?=.*pinecone)/gi,
    label:"[PINECONE_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"SendGrid API Key",
    regex:/\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
    label:"[SENDGRID_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Mailgun API Key",
    regex:/\bkey-[a-f0-9]{32}\b/g,
    label:"[MAILGUN_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Resend API Key",
    regex:/\bre_[A-Za-z0-9]{30,}\b/g,
    label:"[RESEND_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Brevo API Key",
    regex:/\bxkeysib-[A-Za-z0-9]{50,}\b/g,
    label:"[BREVO_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Stripe Restricted Key",
    regex:/\brk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    label:"[STRIPE_RESTRICTED]",
    severity:"critical",
    penalty:30
},

{
    name:"PayPal Client Secret",
    regex:/\bE[A-Za-z0-9_-]{60,}\b/g,
    label:"[PAYPAL_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Razorpay Key",
    regex:/\brzp_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    label:"[RAZORPAY_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Twilio Account SID",
    regex:/\bAC[a-fA-F0-9]{32}\b/g,
    label:"[TWILIO_SID]",
    severity:"warning",
    penalty:10
},

{
    name:"Cloudinary URL",
    regex:/cloudinary:\/\/[^\s"'`]+/gi,
    label:"[CLOUDINARY_URL]",
    severity:"critical",
    penalty:25
},

{
    name:"Supabase API Key",
    regex:/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b(?=.*supabase)/gi,
    label:"[SUPABASE_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Supabase URL",
    regex:/https:\/\/[a-z0-9-]+\.supabase\.co/gi,
    label:"[SUPABASE_URL]",
    severity:"warning",
    penalty:10
},

{
    name:"Notion Secret",
    regex:/\bsecret_[A-Za-z0-9]{40,}\b/g,
    label:"[NOTION_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Linear API Key",
    regex:/\blin_api_[A-Za-z0-9]{30,}\b/g,
    label:"[LINEAR_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Postman API Key",
    regex:/\bPMAK-[A-Za-z0-9-]{40,}\b/g,
    label:"[POSTMAN_KEY]",
    severity:"critical",
    penalty:30
}

];
const devOpsPatterns = [

{
    name:"NPM Token",
    regex:/\bnpm_[A-Za-z0-9]{36}\b/g,
    label:"[NPM_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"PyPI API Token",
    regex:/\bpypi-[A-Za-z0-9_-]{60,}\b/g,
    label:"[PYPI_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"JFrog Token",
    regex:/\bAKCp[A-Za-z0-9]{60,}\b/g,
    label:"[JFROG_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Docker Config Auth",
    regex:/"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"/gi,
    label:"[DOCKER_AUTH]",
    severity:"critical",
    penalty:30
},

{
    name:"Netlify Token",
    regex:/\bnfp_[A-Za-z0-9]{30,}\b/g,
    label:"[NETLIFY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Render API Key",
    regex:/\brnd_[A-Za-z0-9]{30,}\b/g,
    label:"[RENDER_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Fly.io Token",
    regex:/\bfo1_[A-Za-z0-9_-]{40,}\b/g,
    label:"[FLYIO_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Railway Token",
    regex:/\brailway_[A-Za-z0-9_-]{30,}\b/g,
    label:"[RAILWAY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Cloudflare API Token",
    regex:/\bv1\.0-[a-f0-9-]{100,}\b/gi,
    label:"[CLOUDFLARE_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"DigitalOcean Token",
    regex:/\bdo[opr]_v1_[a-f0-9]{64}\b/gi,
    label:"[DIGITALOCEAN_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Heroku API Key",
    regex:/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    label:"[HEROKU_KEY]",
    severity:"warning",
    penalty:10
},

{
    name:"Vercel Token",
    regex:/\bvercel_[A-Za-z0-9]{24,}\b/g,
    label:"[VERCEL_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"CircleCI Token",
    regex:/\b[0-9a-f]{40}\b(?=.*circleci)/gi,
    label:"[CIRCLECI_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Travis Token",
    regex:/\btravis_[A-Za-z0-9]{24,}\b/g,
    label:"[TRAVIS_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Git Credential URL",
    regex:/https?:\/\/[^:\s]+:[^@\s]+@github\.com\/[^\s]+/gi,
    label:"[GIT_CREDENTIAL_URL]",
    severity:"critical",
    penalty:30
},

{
    name:"SSH Public Key",
    regex:/ssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+/g,
    label:"[SSH_PUBLIC_KEY]",
    severity:"info",
    penalty:5
},

{
    name:"SSH Private Key",
    regex:/-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----/g,
    label:"[OPENSSH_PRIVATE_KEY]",
    severity:"critical",
    penalty:35
},

{
    name:"PKCS8 Private Key",
    regex:/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g,
    label:"[PKCS8_PRIVATE_KEY]",
    severity:"critical",
    penalty:35
},

{
    name:"RSA Private Key",
    regex:/-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----/g,
    label:"[RSA_PRIVATE_KEY]",
    severity:"critical",
    penalty:35
},

{
    name:"EC Private Key",
    regex:/-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----/g,
    label:"[EC_PRIVATE_KEY]",
    severity:"critical",
    penalty:35
}

];
const miscPatterns = [

{
    name:"Datadog API Key",
    regex:/\b[a-f0-9]{32}\b(?=.*datadog)/gi,
    label:"[DATADOG_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Datadog Application Key",
    regex:/\b[a-f0-9]{40}\b(?=.*datadog)/gi,
    label:"[DATADOG_APP_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Sentry Auth Token",
    regex:/\bsntrys_[A-Za-z0-9_-]{50,}\b/g,
    label:"[SENTRY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Sentry DSN",
    regex:/https:\/\/[A-Za-z0-9]+@[A-Za-z0-9.-]+\/\d+/gi,
    label:"[SENTRY_DSN]",
    severity:"warning",
    penalty:10
},

{
    name:"Algolia API Key",
    regex:/\b[a-f0-9]{32}\b(?=.*algolia)/gi,
    label:"[ALGOLIA_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Contentful Access Token",
    regex:/\bCFPAT-[A-Za-z0-9]{30,}\b/g,
    label:"[CONTENTFUL_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Fastly API Token",
    regex:/\bFastly\s+[A-Za-z0-9]{20,}\b/g,
    label:"[FASTLY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Mapbox Secret Token",
    regex:/\bsk\.[A-Za-z0-9_-]{50,}\b/g,
    label:"[MAPBOX_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Mapbox Public Token",
    regex:/\bpk\.[A-Za-z0-9_-]{50,}\b/g,
    label:"[MAPBOX_PUBLIC]",
    severity:"warning",
    penalty:10
},

{
    name:"Cloudinary API Secret",
    regex:/cloudinary:\/\/[^:]+:([^@]+)@/gi,
    label:"[CLOUDINARY_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Pusher Secret",
    regex:/\bpusher.*secret.*[:=]\s*["']?([A-Za-z0-9]{20,})/gi,
    label:"[PUSHER_SECRET]",
    severity:"critical",
    penalty:30
},

{
    name:"Sendinblue API Key",
    regex:/\bxkeysib-[A-Za-z0-9]{60,}\b/g,
    label:"[SENDINBLUE_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"OneSignal REST API Key",
    regex:/\b[0-9a-f]{32}\b(?=.*onesignal)/gi,
    label:"[ONESIGNAL_KEY]",
    severity:"critical",
    penalty:30
},

{
    name:"Zoom JWT",
    regex:/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?=.*zoom)/gi,
    label:"[ZOOM_JWT]",
    severity:"warning",
    penalty:15
},

{
    name:"Shopify Access Token",
    regex:/\bshpat_[A-Za-z0-9]{32}\b/g,
    label:"[SHOPIFY_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Asana Personal Access Token",
    regex:/\b1\/[0-9]{16}:[A-Za-z0-9]{32,}\b/g,
    label:"[ASANA_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Atlassian API Token",
    regex:/\bATATT3xFfGF0[A-Za-z0-9_-]{50,}\b/g,
    label:"[ATLASSIAN_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Dropbox Access Token",
    regex:/\bsl\.[A-Za-z0-9_-]{100,}\b/g,
    label:"[DROPBOX_TOKEN]",
    severity:"critical",
    penalty:30
},

{
    name:"Telegram Bot Token",
    regex:/\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    label:"[TELEGRAM_BOT]",
    severity:"critical",
    penalty:30
},

{
    name:"Webhook URL",
    regex:/https:\/\/(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|chat\.googleapis\.com\/v1\/spaces)[^\s"'`]+/gi,
    label:"[WEBHOOK]",
    severity:"critical",
    penalty:25
}

];

//patterns is another js file
patterns.push(
    ...extraPatterns,
    ...databasePatterns,
    ...cloudPatterns,
    ...servicePatterns,
    ...devOpsPatterns,
    ...miscPatterns
);