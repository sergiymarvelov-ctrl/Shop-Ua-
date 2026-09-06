const express=require('express');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const multer=require('multer');
const {Pool}=require('pg');
const path=require('path');

const app=express();
const PORT=process.env.PORT||3000;
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:3*1024*1024}});
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}}):null;
let db={users:[],products:[{id:1,name:'Лавандове мило',price:120,desc:'Натуральне мило ручної роботи з ніжним ароматом лаванди.',image:''},{id:2,name:'Медове мило',price:135,desc:'М’яке натуральне мило з теплим медовим ароматом.',image:''}],orders:[]};

async function load(){
  if(pool){
    await pool.query('CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY, data JSONB NOT NULL)');
    const r=await pool.query('SELECT data FROM app_state WHERE id=1');
    if(r.rows[0]) db=r.rows[0].data;
  }
  if(!db.users.find(u=>u.username==='Yung_Marvelov')){
    db.users.push({id:1,username:'Yung_Marvelov',password:bcrypt.hashSync(process.env.ADMIN_PASSWORD||'ChangeMe123!',10),role:'owner'});
    await save();
  }
}
async function save(){if(pool) await pool.query('INSERT INTO app_state(id,data) VALUES(1,$1::jsonb) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data',[JSON.stringify(db)]);}
const imageData=f=>f?`data:${f.mimetype};base64,${f.buffer.toString('base64')}`:'';
app.use(express.urlencoded({extended:true,limit:'5mb'})); app.use(express.json({limit:'5mb'}));
app.use(session({secret:process.env.SESSION_SECRET||'change-this-secret-before-public-use',resave:false,saveUninitialized:false,cookie:{sameSite:'lax',secure:false,maxAge:7*24*60*60*1000}}));
app.use(express.static(path.join(__dirname,'public')));
const me=req=>db.users.find(u=>u.id===req.session.uid);
const admin=(req,res,next)=>{const u=me(req);if(!u||!['admin','owner'].includes(u.role))return res.status(403).json({error:'Немає доступу'});req.user=u;next();};
app.get('/health',(req,res)=>res.json({ok:true,database:!!pool}));
app.get('/api/me',(req,res)=>{const u=me(req);res.json(u?{username:u.username,role:u.role}:null)});
app.get('/api/products',(req,res)=>res.json(db.products));
app.post('/api/register',async(req,res)=>{try{let {username,password}=req.body;username=(username||'').trim();if(!username||!password||password.length<6)return res.status(400).json({error:'Мінімум 6 символів'});if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(400).json({error:'Такий користувач існує'});const u={id:Date.now(),username,password:await bcrypt.hash(password,10),role:'user'};db.users.push(u);await save();req.session.uid=u.id;res.json({ok:true});}catch(e){res.status(500).json({error:'Помилка сервера'})}});
app.post('/api/login',async(req,res)=>{const u=db.users.find(x=>x.username.toLowerCase()===(req.body.username||'').toLowerCase());if(!u||!(await bcrypt.compare(req.body.password||'',u.password)))return res.status(401).json({error:'Невірний логін або пароль'});req.session.uid=u.id;res.json({ok:true,role:u.role})});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.post('/api/products',admin,upload.single('image'),async(req,res)=>{db.products.push({id:Date.now(),name:req.body.name,price:Number(req.body.price)||0,desc:req.body.desc||'',image:imageData(req.file)});await save();res.redirect('/admin.html')});
app.post('/api/products/:id',admin,upload.single('image'),async(req,res)=>{const p=db.products.find(x=>x.id==req.params.id);if(!p)return res.status(404).end();if(req.body.name)p.name=req.body.name;if(req.body.price!==undefined&&req.body.price!=='')p.price=Number(req.body.price);if(req.body.desc!==undefined)p.desc=req.body.desc;if(req.file)p.image=imageData(req.file);await save();res.redirect('/admin.html')});
app.delete('/api/products/:id',admin,async(req,res)=>{db.products=db.products.filter(x=>x.id!=req.params.id);await save();res.json({ok:true})});
app.get('/api/users',admin,(req,res)=>res.json(db.users.map(({password,...u})=>u)));
app.post('/api/admins',admin,async(req,res)=>{if(req.user.role!=='owner')return res.status(403).json({error:'Тільки головний адміністратор'});let {username,password}=req.body;username=(username||'').trim();if(!username||!password||password.length<6)return res.status(400).json({error:'Логін і пароль від 6 символів'});if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(400).json({error:'Користувач існує'});db.users.push({id:Date.now(),username,password:await bcrypt.hash(password,10),role:'admin'});await save();res.json({ok:true})});
app.post('/api/orders',async(req,res)=>{const {items,name,phone}=req.body;if(!Array.isArray(items)||!items.length)return res.status(400).json({error:'Кошик порожній'});db.orders.push({id:Date.now(),items,name,phone,status:'Нове',created:new Date().toISOString()});await save();res.json({ok:true})});
app.get('/api/orders',admin,(req,res)=>res.json(db.orders));
load().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log('SOAP SHOP running on port '+PORT))).catch(e=>{console.error(e);process.exit(1)});
