#!/bin/bash

clear
echo -e "\e[1;36mMERN stack installer\e[0m"
echo ""
# check node js
command -v node >/dev/null || (echo -e "\e[1;31mNode js not found! run \"sudo apt install nodejs-lts\" to install it.\e[0m" && exit 0)
# check npm js
command -v npm >/dev/null|| (echo -e "\e[1;31mNpm js not found! run \"sudo apt install npm\" to install it.\e[0m" && exit 0)
# check yarn js
isYarn= command -v yarn >/dev/null
$isYarn || (echo -e "\e[1;31myarn js not found & I recommend to install yarn because yarn is more performance and faster than npm. Run \"sudo npm i -g yarn\" to install yarn and in this time I will install all dependencies with npm.\e[0m" && exit 0)
read -p "Enter you project name : " dirName
rm -rf $dirName
mkdir $dirName
chmod +rwx $dirName && cd $dirName
#make necessary directory
mkdir -p server server/{bin,configs,routes,models,services,utils,helpers,public} "test"

#functions
#  creaded file
CreatedFile() {
  echo ""
  echo -e "\e[1;34mCreated: \e[0m" $1
}

# create package.json
PackageFile () {
  packageFile= echo -e "{
    \"name\": \"$dirName\",
    \"version\": \"1.0.0\",
    \"author\": \"\",
    \"description\": \"\",
    \"private:\": \"true\",
    \"type\": \"module\",
    \"license\": \"MIT\",
    \"scripts\": {
      \"client\": \"cd client && $1 dev\",
      \"server\": \"mongod & nodemon --experimental-modules /server/bin/www.js\",
      \"dev\": \"concurrently -n 'client,server' -c 'green,yellow' \\\"$1 client\\\" \\\"$1 server\\\"\",
      \"key:gen\": \"cd server/helpers && node keyGen.js\",
      \"del:users\": \"cd server/helpers && node deleteAllUsers.js\",
      \"add:users\": \"cd server/helpers && node addUsers.js\"
    }
  }" > package.json
}

# create server Devdependencies
ServerDevDepenedices() {
  $1 $2 -D nodemon >/dev/null 
}

# create server Dependencies
ServerDependencies() {
  $1 $2 bcrypt body-parser compression cookie-parser cors csurf dotenv express express-async-handler express-jwt express-mongo-sanitize express-rate-limit express-session helmet hpp http-errors joi jsonwebtoken lodash mongoose morgan multer sanitize-html toobusy-js >/dev/null 
}

# create yarn react installer
YarnReactInstaller() {
  yarn create vite client --template react >/dev/null 
}

# create nom react installer
NpmReactInstaller() {
  npm init vite@latest client -- --template react >/dev/null 
}

# create client dependencies 
ClientDependencies() {
  $1 $2 @emotion/styled @emotion/react @material-ui/core@next @material-ui/icons @material-ui/lab@next axios formik formik-material-ui material-ui-image react-helmet react-router-dom react-redux react-spinners redux redux-thunk redux-devtools-extension yup >/dev/null 
}

# installing process
if ping -c 1 -q google.com >&/dev/null;then
  echo ""
  echo -e "\e[1;33mInstalling dependencies, please wait....\e[0m"
  echo ""
  if $isYarn; then 
    PackageFile yarn 
    echo "package.json is created"
    echo ""
    echo "installing devdependencies for server"
    echo ""
    ServerDevDepenedices yarn add 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing dependencies for server"
    echo ""
    ServerDependencies yarn add 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing react for client"
    echo ""
    YarnReactInstaller 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    cd client 
    yarn >/dev/null
    echo "installing dependencies for client"
    echo ""
    ClientDependencies yarn add 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    cd ..
  else 
    echo "package.json is created"
    echo ""
    echo "installing devdependencies for server"
    echo ""
    PackageFile npm 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing devdependencies for server"
    echo ""
    ServerDevDepenedices npm install 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing dependencies for server"
    echo ""
    ServerDependencies npm install 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing react for client"
    echo ""
    NpmReactInstaller 
    cd client 
    npm install >/dev/null 
    echo -e "\e[32mfinished\e[0m"
    echo ""
    echo "installing dependencies for client"
    echo ""
    ClientDependencies npm install 
    echo -e "\e[32mfinished\e[0m"
    cd ..
  fi
else 
  echo ""
  echo "Network Problem, need good network connection" 
  echo ""
  cd .. && rm -rf $dirName
  exit 0
fi

#clear

echo ""

# create nodemon.json
echo -e "{
\"verbose\": false,
\"watch\": \"server/*\",
\"ignore\": [\"node_modules\", \"assets\", \"helpers\"],
\"exec\": \"node\"
}" > nodemon.json
  
# create server/bin/www.js
echo -e "#!usr/bin/env node
\"use strict\";
import \"../utils/db.js\"
import app from \"../app.js\";
import config from \"../configs/config.js\";
import http from \"http\";
import toobusy from \"toobusy-js\";

const port = config.port;
app.set('port', port);

// create server 
const server = http.createServer(app);

server.listen(port, err => {
   if(err) {
     console.error(err);
     return process.exit(0)
   };
   return console.log(\` \\\n🚀 @ http://127.0.0.1:${port}\`);
});

process.on(\"SIGINT\", () => {
   server.close();
   console.warn(\"💔 Server closed!\\\n\");
   toobusy.shutdown();
   process.exit(0);
});" > server/bin/www.js

# create server/app.js 
echo -e "\"use strict\";
import express from \"express\";
import cors from \"cors\";
import config from \"./configs/config.js\";
import logger from \"morgan\";
import bodyParser from \"body-parser\";
import cookieParser from \"cookie-parser\";
import helmet from \"helmet\";
import hpp from \"hpp\";
import mongoSanitize from \"express-mongo-sanitize\";
import session from \"express-session\";
import csrf from \"csurf\";
import rateLimit from \"express-rate-limit\";
import compression from \"compression\";
import path from \"path\";
import toobusy from \"toobusy-js\";
import createError from \"http-errors\";
import authRoute from \"./routes/auth.route.js\";

/***
* configuration section
* */

const corsOpts = {
  origin: config.clientUri,
  methods: [\"GET\", \"POST\", \"PATCH\", \"DELETE\"]
};

const urlOpts = {
  extended: true,
  limit: '1kb'
};

const jsonOpts = {
limit: '1kb'
};

const sessionOpts = {
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: true
    }
};

const csrfProtection = csrf({
  cookie: true,
  secure: true,
  httpOnly: true,
  sameSite: true
});

const limiter = rateLimit({
  windowMs: 10 * 60 *1000,
  max: 100
});

const xApiKey = (req, res, next) => {
  const apiKey = new Map();
  apiKey.set(config.xApiKey, true);
  const keyId = req.get('x-api-key');
  if(!apiKey.has(keyId)) throw createError.NotAcceptable('Not acceptable without vaild api key!');
  return next();
};

const serverBusy = (req, res, next) => {
  if(toobusy()) throw createError.ServiceUnavailable(\"I'm busy right now, sorry.\");
  return next();
};

// cwd => current working directory = __dirname
const cwd = process.cwd();

const app = express();

/***
* middleware section
* */

app.set('trust proxy', 1);
app.use(cors(corsOpts));
app.use(logger('dev'));
app.use(bodyParser.json(jsonOpts));
app.use(bodyParser.urlencoded(urlOpts));
app.use(cookieParser());
app.use(helmet());
app.use(hpp());
app.use(mongoSanitize());
app.use(session(sessionOpts));
app.use(csrfProtection);
app.use(xApiKey);
app.use(serverBusy);
app.use(limiter);
app.use(compression());
app.use(express.static(path.join(cwd, 'public')));

/***
* router section
* */

//default route
app.use('/', (req, res, next) =>{
  res.json({\"hello\":\"world\"})
  return next()
})
// token router (eg- csrf)
app.use('/', authRoute);
//404 and error handler
app.use((req, res, next) => {
  next(createError.NotFound())
});

app.use((err, req, res, next) => {
  res.status = err.status || 500;
  res.json({
    status: err.status || 500,
    message: err.message
  });
});

export default app;" > server/app.js

# create server/configs/config.js
echo -e "\"use strict\"
import dotenv from \"dotenv\";

dotenv.config();

const config = {
  port: process.env.PORT || '8000',
  clientUri: process.env.CLIENT_URI || 'http://127.0.0.1:3000',
  dbUri: process.env.DB_URI || 'mongodb://127.0.0.1:27017/$dirName',
  sessionSecret: process.env.SESSION_SECRET || 'your session secret key',
  xApiKey: process.env.X_API_KEY || 'your x api key', 
  jwtSecret: process.env.JWT_SECRET || 'your jwt secret key',
  saltRound: +process.env.SALT_ROUND || 10
};

 export default config;" > server/configs/config.js
 
# create server/utils/db.js
echo -e "\"use strict\";
import mongoose from \"mongoose\";
import config from \"../configs/config.js\";

mongoose.connect(config.dbUri, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true
})

mongoose.connection.on(\"error\", async (err) => {
  console.error(err)
  await mongoose.connection.close()
})

mongoose.connection.on(\"disconnected\", () => {
console.warn(\"\\\n🔥 Disconnected from DB!\\\n\");
});

mongoose.connection.on(\"connected\", () => console.info(\"\\\n🦄 mongoose is connected to DB\\\n\"))

process.on(\"SIGINT\", async () => {
  await mongoose.connection.close();
process.exit(0);
})" > server/utils/db.js

# created server/utils/validateSchema.js
echo -e "\"use strict\";
import Joi from \"joi\";
import sanitizer from \"./sanitizer.js\";

const joi = Joi.extend(sanitizer);

// now you can use .escapeHTML() for escaping html tag

// example 👇
/***
* message = joi.string().max(120).escapeHTML()
* */
" > server/utils/validateSchema.js

# create server/utils/sanitizer.js 
echo -e "\"use strict\";
import sanitizeHtml from \"sanitize-html\";

const sanitizing = (joi) => ({
  type: 'string',
  base: joi.string(),
  messages: {
    'string.escapeHTML': '{{#label}} must not include HTML!'
  },
  rules: {
    escapeHTML: {
      validate(value, helpers) {
        const clean = sanitizeHtml(value, {
        allowedTags: [],
        allowedAttributes: {},
        });
        if (clean !== value) return helpers.error('string.escapeHTML', { value })
        return clean;
      }
    }
  }
});

export default sanitizing;
" > server/utils/sanitizer.js

# create server/routes/auth.route.js
echo -e "\"use strict\";
import {Router} from \"express\";
import service from \"../services/auth.service.js\";

const router = Router();

router.route(\"/api/auth/csrftoken\").get(service.csrfToken);

export default router;
" > server/routes/auth.route.js

# create server/services/auth.service.js
echo "\"use strict\";
import createError from \"http-errors\"

const csrfToken = (req, res, next) => {
 try{
    res.json({\"csrf-token\": req.csrfToken()})
    return next()
  }catch(err) {
  return next(createError.InternalServerError())
  }
}

export default {csrfToken}
" > server/services/auth.service.js

# create server/models/User.model.js
echo -e "import mongoose from \"mongoose\";
import bcrypt from \"bcrypt\";
import config from \"../configs/config.js\";

const schema = mongoose.Schema;

const userSchema = new schema({
  name:{
   type: String,
    trim: true,
    required: true
  },
  email: {
    type: String,
    lowercase: true,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required:true
  }
},{
  timestamps: true
});

userSchema.pre('save', async function (next) {
  try{
   if(this.isNew) {
      const salt = await bcrypt.genSalt(config.saltRound);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      this.password = hashedPassword;
    }
    next()
  }catch(err){
    next(err);
  }
});

userSchema.methods.isValidPassword = async function (pwd) {
  try{
    return await bcrypt.compare(pwd, this.password);
  }catch(err){
    throw(err);
  }
};

export default mongoose.model('User', userSchema);
" > server/models/User.model.js

# create server/helpers/deleteAllUsers.js
echo -e "\"use strict\";
import \"../utils/db.js\";
import mongoose from \"mongoose\";
import User from \"../models/User.model.js\";

const deleteAllUsers = async () => {
  console.log('\\\n... Start working ...\\\n');
  try{
    await User.deleteMany();
    console.log('... Success, all user deleted ...');
  }catch(err){
    return console.error(err)
  }
  await mongoose.connection.close();
  console.log(\"... process exist ...\\\n\");
  process.exit(0);
}

deleteAllUsers();
" > server/helpers/deleteAllUsers.js

# server/helpers/keyGen.js 
echo -e "\"use strict\";
import crypto from \"crypto\";

const generator = no => {
  const result = crypto.randomBytes(no).toString('hex');
  return result;
};

const apikey = generator(10);
const jwtkey = generator(10);
const sessionkey = generator(10);

console.log('\\\n... Start working ...\\\n');
console.table({apikey, jwtkey, sessionkey})
console.log('\\\n... process exit ...\\\n')
 process.exit(0)" > server/helpers/keyGen.js
 
# create client/.env 
echo -e "SKIP_PREFLIGHT_CHECK=true" > client/.env

 # create NOTICE.TXT
echo -e "***Before starting application, please read notice file***

1. If you are not using local mongo db, delete \"mongod & \" in $dirName/package.json file

2. Change your custom configuration in \"server/configs/config.js\" or create \"$dirName\.env\" file. By default db name is project name \"$dirName\" and using local mongo db \"mongodb://127.0.0.1:27017/$dirName\"

3. I created some helpful file for you that is if you don't know to use what custom secret key (for session, api, jwt), you can use my help. open terminal and make sure working directory is \"$dirName\" and run this command \"yarn key:gen\" then you will see random secret key. And then copy and paste in config.js

4. I created another helper is delete all users in db if you need delted all user in User document in db run \"yarn del:users\"

5. I don't add any production level scripts command in package.json. So if you want, you need to customize package.json

6. if you don't want to use api key and csurf protection comment in \"server/app.js\"

7. x-api-key need every req methods. usage is in req header => name is \"x-api-key\" value is \"your secret key in config.js or .env\"

8. csrf protection also too but only \"GET\" method req doesn't need. In other req, usage is in header => name is \"csrf-token\" and paste value which is copied from \"api/auth/csrftoken\" method is GET.
" > NOTICE.txt

echo -e "node_modules
build" > .gitignore

clear

git init >/dev/null
git add . >/dev/null
git commit -m "set up complete, ready to use" >/dev/null 
git branch -M main >/dev/null 
echo "Do you want to push your project to github?"
read -p "y|N : " pushToGithub

case $pushToGithub in 
[y|Y][e|E][s|S])
echo ""
echo "Enter your github repo link (ssh/https)"
read repoLink
git remote add origin $repoLink
git push -u origin main
;;
[n|N][o|O])
echo ""
;;
*)
echo ""
;;
esac

clear

CreatedFile "$dirName/package.json"
CreatedFile "$dirName/nodemon.json"
CreatedFile "$dirName/server/bin/www.js"
CreatedFile "$dirName/server/app.js"
CreatedFile "$dirName/server/configs/config.js"
CreatedFile "$dirName/server/utils/db.js"
CreatedFile "$dirName/server/utils/validateSchema.js"
CreatedFile "$dirName/server/utils/sanitizer.js"
CreatedFile "$dirName/server/routes/auth.route.js"
CreatedFile "$dirName/server/routes/auth.service.js"
CreatedFile "$dirName/server/models/User.model.js"
CreatedFile "$dirName/server/helpers/deleteAllUsers.js"
CreatedFile "$dirName/server/helpers/keyGen.js"
CreatedFile "$dirName/client/.env"
CreatedFile "$dirName/NOTICE.txt"
CreatedFile "$dirName/.gitignore"

echo ""
echo "go to directory"
echo -e "\e[1;32m\"cd $dirName\"\e[0m"
echo ""

if $isYarn; then
  echo "run client only"
  echo -e "\e[1;32mcd \"yarn client\"\e[0m"
  echo ""
  echo "run server only"
  echo -e "\e[1;32m\"yarn server\"\e[0m"
  echo ""
  echo "both server and client"
  echo -e "\e[1;32m\"yarn dev\"\e[0m"
  echo ""
else 
  echo "run client only"
  echo -e "\e[1;32m\"npm run client\e[0m"
  echo ""
  echo "run server only"
  echo -e "\e[1;32m\"npm run server\"\e[0m"
  echo ""
  echo -e "\e[1;32m\"yarn server\"\e[0m"
  echo ""
  echo "both server and client"
  echo -e "\e[1;32m\"npm run dev\"\e[0m"
  echo ""
fi

echo -e "First of all, please read \e[1;31mNOTICE.TXT\e[0m file."
echo ""

exit 0