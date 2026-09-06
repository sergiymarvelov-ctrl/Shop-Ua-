const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const multer=require("multer");
const {Pool}=require("pg");
const path=require("path");

const app=express();
const PORT=process.env.PORT||3000;
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}}):null;
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:3*1024*1024}});

let db={
 users:[], products:[
  {id:1,name:"Лавандове мило",price:120,desc:"Натуральне мило ручної роботи з ароматом лаванди.",image:""},
  {id:2,name:"Медове мило",price:135,desc:"Ніжне мило ручної роботи з медовим ароматом.",image:""}
 ],
 orders:[], promos:[],
 settings:{shopName:"SYSTR",subtitle:"СЮСТР — майстерня натурального мила",background:"#faf7ef",pickupText:"Забрати можна в Надвірній.",contactText:"Спосіб зв’язку уточнюється адміністратором."}
};

app.set("trust proxy",1);
app.use(express.json({limit:"5mb"}));
app.use(express.urlencoded({extended:true,limit:"5mb"}));
app.use(session({
 secret:process.env.SESSION_SECRET||"change-me-systr",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*86400000}
}));
app.use(express.static(__dirname));

async function save(){
 if(pool) await pool.query("INSERT INTO app_state(id,data) VALUES(1,$1::jsonb) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data",[JSON.stringify(db)]);
}
async function load(){
 if(pool){
  await pool.query("CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY,data JSONB NOT NULL)");
  const r=await pool.query("SELECT data FROM app_state WHERE id=1");
  if(r.rows[0]) db=r.rows[0].data;
 }
 db.promos ||= []; db.orders ||= []; db.products ||= []; db.users ||= [];
 db.settings ||= {shopName:"SYSTR",subtitle:"СЮСТР — майстерня натурального мила",background:"#faf7ef",pickupText:"Забрати можна в Надвірній.",contactText:"Спосіб зв’язку уточнюється адміністратором."};
 const owner=db.users.find(u=>u.username.toLowerCase()==="yung_marvelov");
 const desired=process.env.ADMIN_PASSWORD||"ChangeMe123!";
 if(!owner){
  db.users.push({id:Date.now(),username:"Yung_Marvelov",phone:"",name:"Yung_Marvelov",password:await bcrypt.hash(desired,10),role:"owner",theme:"light",usedPromos:[],created:new Date().toISOString()});
  await save();
 } else if(process.env.RESET_OWNER_PASSWORD==="true"){
  owner.password=await bcrypt.hash(desired,10); await save();
 }
}
const me=req=>db.users.find(u=>String(u.id)===String(req.session.uid));
const auth=(req,res,next)=>{const u=me(req);if(!u)return res.status(401).json({error:"Потрібно увійти"});req.user=u;next()};
const admin=(req,res,next)=>{const u=me(req);if(!u||!["admin","owner"].includes(u.role))return res.status(403).json({error:"Немає доступу"});req.user=u;next()};
const safeUser=u=>({id:u.id,username:u.username,phone:u.phone,name:u.name||u.username,role:u.role,theme:u.theme||"light"});
const img=f=>f?`data:${f.mimetype};base64,${f.buffer.toString("base64")}`:"";

app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.get("/api/settings",(req,res)=>res.json(db.settings));
app.get("/api/products",(req,res)=>res.json(db.products));
app.get("/api/me",(req,res)=>{const u=me(req);res.json(u?safeUser(u):null)});

app.post("/api/register",async(req,res)=>{
 try{
  let phone=String(req.body.phone||"").trim(), username=String(req.body.username||"").trim(), password=String(req.body.password||"");
  if(phone.length<7)return res.status(400).json({error:"Вкажіть коректний номер телефону"});
  if(username.length<3)return res.status(400).json({error:"Логін — мінімум 3 символи"});
  if(password.length<6)return res.status(400).json({error:"Пароль — мінімум 6 символів"});
  if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(400).json({error:"Такий логін уже зайнятий"});
  if(db.users.some(u=>u.phone&&u.phone===phone))return res.status(400).json({error:"Цей номер уже зареєстрований"});
  const u={id:Date.now(),username,phone,name:username,password:await bcrypt.hash(password,10),role:"user",theme:"light",usedPromos:[],created:new Date().toISOString()};
  db.users.push(u); await save(); req.session.uid=u.id;
  req.session.save(()=>res.json({ok:true,user:safeUser(u)}));
 }catch(e){console.error(e);res.status(500).json({error:"Помилка реєстрації"})}
});
app.post("/api/login",async(req,res)=>{
 const login=String(req.body.login||req.body.username||"").trim(), password=String(req.body.password||"");
 const u=db.users.find(x=>x.username.toLowerCase()===login.toLowerCase()||x.phone===login);
 if(!u||!await bcrypt.compare(password,u.password))return res.status(401).json({error:"Невірний логін/номер або пароль"});
 req.session.uid=u.id; req.session.save(()=>res.json({ok:true,user:safeUser(u)}));
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.patch("/api/profile",auth,async(req,res)=>{
 const name=String(req.body.name||"").trim(), theme=req.body.theme;
 if(name) req.user.name=name.slice(0,50);
 if(["light","dark"].includes(theme))req.user.theme=theme;
 await save(); res.json({ok:true,user:safeUser(req.user)});
});

app.get("/api/my-orders",auth,(req,res)=>res.json(db.orders.filter(o=>String(o.userId)===String(req.user.id)).sort((a,b)=>b.id-a.id)));

app.get("/api/rewards",auth,(req,res)=>{
 const completed=db.orders.filter(o=>String(o.userId)===String(req.user.id)&&o.status!=="Скасовано");
 const count=completed.reduce((n,o)=>n+(o.items||[]).reduce((s,i)=>s+(Number(i.qty)||1),0),0);
 const used=(req.user.usedPromos||[]).length>0;
 res.json([
  {title:"Зареєструватися на сайті",done:true},
  {title:"Придбати 1 товар",done:count>=1},
  {title:"Придбати 5 товарів",done:count>=5},
  {title:"Придбати 10 товарів",done:count>=10},
  {title:"Використати перший промокод",done:used}
 ]);
});

app.post("/api/promo/use",auth,async(req,res)=>{
 const code=String(req.body.code||"").trim().toUpperCase();
 const p=db.promos.find(x=>x.code===code&&x.active!==false);
 if(!p)return res.status(404).json({error:"Промокод не знайдено"});
 req.user.usedPromos ||= [];
 if(!req.user.usedPromos.includes(code))req.user.usedPromos.push(code);
 await save(); res.json({ok:true,promo:{code:p.code,description:p.description,discount:p.discount}});
});

app.post("/api/orders",auth,async(req,res)=>{
 const b=req.body, ids=Array.isArray(b.items)?b.items:[];
 if(!ids.length)return res.status(400).json({error:"Кошик порожній"});
 if(!String(b.firstName||"").trim()||!String(b.lastName||"").trim()||!String(b.phone||"").trim())return res.status(400).json({error:"Заповніть ім’я, прізвище та телефон"});
 if(!["pickup","nova"].includes(b.delivery))return res.status(400).json({error:"Оберіть доставку"});
 if(b.delivery==="nova"&&(!String(b.city||"").trim()||!String(b.branch||"").trim()))return res.status(400).json({error:"Вкажіть населений пункт і відділення"});
 const items=[];
 for(const id of ids){const p=db.products.find(x=>String(x.id)===String(id));if(p)items.push({id:p.id,name:p.name,price:p.price,qty:1})}
 if(!items.length)return res.status(400).json({error:"Товари не знайдено"});
 let discount=0,promoCode="";
 if(b.promo){const p=db.promos.find(x=>x.code===String(b.promo).trim().toUpperCase()&&x.active!==false);if(p){discount=Math.max(0,Math.min(100,Number(p.discount)||0));promoCode=p.code;req.user.usedPromos ||= [];if(!req.user.usedPromos.includes(p.code))req.user.usedPromos.push(p.code)}}
 const subtotal=items.reduce((s,i)=>s+Number(i.price),0), total=Math.round(subtotal*(100-discount))/100;
 const order={id:Date.now(),userId:req.user.id,items,firstName:String(b.firstName).trim(),lastName:String(b.lastName).trim(),phone:String(b.phone).trim(),delivery:b.delivery,city:String(b.city||"").trim(),branch:String(b.branch||"").trim(),promo:promoCode,discount,total,status:"Нове",created:new Date().toISOString()};
 db.orders.push(order);await save();res.json({ok:true,orderId:order.id});
});

app.post("/api/products",admin,upload.single("image"),async(req,res)=>{
 const price=Number(req.body.price);if(!req.body.name||!Number.isFinite(price))return res.status(400).send("Некоректні дані");
 db.products.push({id:Date.now(),name:String(req.body.name).trim(),price,desc:String(req.body.desc||""),image:img(req.file)});await save();res.redirect("/admin.html");
});
app.post("/api/products/:id",admin,upload.single("image"),async(req,res)=>{
 const p=db.products.find(x=>String(x.id)===String(req.params.id));if(!p)return res.status(404).end();
 if(req.body.name)p.name=String(req.body.name).trim();if(req.body.price!=="")p.price=Number(req.body.price);if(req.body.desc!==undefined)p.desc=String(req.body.desc);if(req.file)p.image=img(req.file);await save();res.redirect("/admin.html");
});
app.delete("/api/products/:id",admin,async(req,res)=>{db.products=db.products.filter(x=>String(x.id)!==String(req.params.id));await save();res.json({ok:true})});
app.get("/api/orders",admin,(req,res)=>res.json([...db.orders].sort((a,b)=>b.id-a.id)));
app.patch("/api/orders/:id",admin,async(req,res)=>{const o=db.orders.find(x=>String(x.id)===String(req.params.id));if(!o)return res.status(404).json({error:"Не знайдено"});o.status=String(req.body.status||o.status);await save();res.json({ok:true})});
app.get("/api/promos",admin,(req,res)=>res.json(db.promos));
app.post("/api/promos",admin,async(req,res)=>{
 const code=String(req.body.code||"").trim().toUpperCase(),description=String(req.body.description||"").trim(),discount=Number(req.body.discount)||0;
 if(!code)return res.status(400).json({error:"Вкажіть код"});if(db.promos.some(p=>p.code===code))return res.status(400).json({error:"Такий промокод існує"});
 db.promos.push({id:Date.now(),code,description,discount,active:true});await save();res.json({ok:true});
});
app.post("/api/admins",admin,async(req,res)=>{
 if(req.user.role!=="owner")return res.status(403).json({error:"Тільки головний адміністратор"});
 let username=String(req.body.username||"").trim(),password=String(req.body.password||"");
 if(username.length<3||password.length<6)return res.status(400).json({error:"Перевірте логін і пароль"});
 if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(400).json({error:"Користувач існує"});
 db.users.push({id:Date.now(),username,phone:"",name:username,password:await bcrypt.hash(password,10),role:"admin",theme:"light",usedPromos:[],created:new Date().toISOString()});await save();res.json({ok:true});
});
app.patch("/api/settings",admin,async(req,res)=>{
 for(const k of ["shopName","subtitle","background","pickupText","contactText"])if(req.body[k]!==undefined)db.settings[k]=String(req.body[k]);
 await save();res.json({ok:true,settings:db.settings});
});

app.use((e,req,res,next)=>{console.error(e);res.status(500).json({error:e.message||"Помилка сервера"})});
load().then(()=>app.listen(PORT,"0.0.0.0",()=>console.log("SYSTR online:",PORT))).catch(e=>{console.error(e);process.exit(1)});