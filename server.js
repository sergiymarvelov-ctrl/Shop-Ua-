const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const multer=require("multer");
const {Pool}=require("pg");
const path=require("path");

const app=express();
const PORT=process.env.PORT||3000;

const pool=process.env.DATABASE_URL
 ? new Pool({
    connectionString:process.env.DATABASE_URL,
    ssl:{rejectUnauthorized:false}
   })
 : null;

const upload=multer({
 storage:multer.memoryStorage(),
 limits:{fileSize:3*1024*1024}
});

let db={
 users:[],
 products:[
  {
   id:1,
   name:"Лавандове мило",
   price:120,
   desc:"Натуральне мило ручної роботи з ароматом лаванди.",
   image:""
  },
  {
   id:2,
   name:"Медове мило",
   price:135,
   desc:"Ніжне мило ручної роботи з медовим ароматом.",
   image:""
  }
 ],
 orders:[],
 promos:[],
 settings:{
  shopName:"SYSTR",
  subtitle:"СЮСТР — майстерня натурального мила",
  background:"#faf7ef",
  pickupText:"Забрати можна в Надвірній.",
  contactText:"Спосіб зв’язку уточнюється адміністратором."
 }
};

app.set("trust proxy",1);

app.use(express.json({limit:"5mb"}));
app.use(express.urlencoded({
 extended:true,
 limit:"5mb"
}));

app.use(session({
 secret:process.env.SESSION_SECRET||"change-me-systr",
 resave:false,
 saveUninitialized:false,
 cookie:{
  httpOnly:true,
  sameSite:"lax",
  secure:process.env.NODE_ENV==="production",
  maxAge:7*86400000
 }
}));

app.use(express.static(__dirname));

async function save(){
 if(pool){
  await pool.query(
   "INSERT INTO app_state(id,data) VALUES(1,$1::jsonb) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data",
   [JSON.stringify(db)]
  );
 }
}

async function load(){
 if(pool){
  await pool.query(
   "CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY,data JSONB NOT NULL)"
  );

  const r=await pool.query(
   "SELECT data FROM app_state WHERE id=1"
  );

  if(r.rows[0]){
   db=r.rows[0].data;
  }
 }

 db.promos ||= [];
 db.orders ||= [];
 db.products ||= [];
 db.users ||= [];

 db.settings ||= {
  shopName:"SYSTR",
  subtitle:"СЮСТР — майстерня натурального мила",
  background:"#faf7ef",
  pickupText:"Забрати можна в Надвірній.",
  contactText:"Спосіб зв’язку уточнюється адміністратором."
 };

 const owner=db.users.find(
  u=>u.username.toLowerCase()==="yung_marvelov"
 );

 const desired=
  process.env.ADMIN_PASSWORD||
  "ChangeMe123!";

 if(!owner){
  db.users.push({
   id:Date.now(),
   username:"Yung_Marvelov",
   phone:"",
   name:"Yung_Marvelov",
   password:await bcrypt.hash(desired,10),
   role:"owner",
   theme:"light",
   usedPromos:[],
   created:new Date().toISOString()
  });

  await save();
 }
 else if(process.env.RESET_OWNER_PASSWORD==="true"){
  owner.password=await bcrypt.hash(desired,10);
  await save();
 }
}

const me=req=>
 db.users.find(
  u=>String(u.id)===String(req.session.uid)
 );

const auth=(req,res,next)=>{
 const u=me(req);

 if(!u){
  return res.status(401).json({
   error:"Потрібно увійти"
  });
 }

 req.user=u;
 next();
};

const admin=(req,res,next)=>{
 const u=me(req);

 if(!u||!["admin","owner"].includes(u.role)){
  return res.status(403).json({
   error:"Немає доступу"
  });
 }

 req.user=u;
 next();
};

const safeUser=u=>({
 id:u.id,
 username:u.username,
 phone:u.phone,
 name:u.name||u.username,
 role:u.role,
 theme:u.theme||"light"
});

const img=f=>
 f
 ? `data:${f.mimetype};base64,${f.buffer.toString("base64")}`
 : "";

app.get("/",(req,res)=>
 res.sendFile(
  path.join(__dirname,"index.html")
 )
);

app.get("/api/health",(req,res)=>{
 res.json({
  ok:true,
  service:"SYSTR",
  auth:true
 });
});

app.get("/api/settings",(req,res)=>{
 res.json(db.settings);
});

app.get("/api/products",(req,res)=>{
 res.json(db.products);
});

app.get("/api/me",(req,res)=>{
 const u=me(req);
 res.json(u?safeUser(u):null);
});

app.post("/api/register",async(req,res)=>{
 try{
  let phone=String(
   req.body.phone||""
  ).trim();

  let username=String(
   req.body.username||""
  ).trim();

  let password=String(
   req.body.password||""
  );

  if(phone.length<7){
   return res.status(400).json({
    error:"Вкажіть коректний номер телефону"
   });
  }

  if(username.length<3){
   return res.status(400).json({
    error:"Логін — мінімум 3 символи"
   });
  }

  if(password.length<6){
   return res.status(400).json({
    error:"Пароль — мінімум 6 символів"
   });
  }

  if(
   db.users.some(
    u=>
     u.username.toLowerCase()===
     username.toLowerCase()
   )
  ){
   return res.status(400).json({
    error:"Такий логін уже зайнятий"
   });
  }

  if(
   db.users.some(
    u=>u.phone&&u.phone===phone
   )
  ){
   return res.status(400).json({
    error:"Цей номер уже зареєстрований"
   });
  }

  const u={
   id:Date.now(),
   username,
   phone,
   name:username,
   password:await bcrypt.hash(password,10),
   role:"user",
   theme:"light",
   usedPromos:[],
   created:new Date().toISOString()
  };

  db.users.push(u);

  await save();

  req.session.uid=u.id;

  req.session.save(()=>{
   res.json({
    ok:true,
    user:safeUser(u)
   });
  });

 }catch(e){
  console.error("REGISTER ERROR:",e);

  res.status(500).json({
   error:"Помилка реєстрації на сервері"
  });
 }
});

app.post("/api/login",async(req,res)=>{
 const login=String(
  req.body.login||
  req.body.username||
  ""
 ).trim();

 const password=String(
  req.body.password||""
 );

 const u=db.users.find(
  x=>
   x.username.toLowerCase()===
   login.toLowerCase()
   ||
   x.phone===login
 );

 if(
  !u||
  !await bcrypt.compare(password,u.password)
 ){
  return res.status(401).json({
   error:"Невірний логін/номер або пароль"
  });
 }

 req.session.uid=u.id;

 req.session.save(()=>{
  res.json({
   ok:true,
   user:safeUser(u)
  });
 });
});

app.post("/api/logout",(req,res)=>{
 req.session.destroy(()=>{
  res.json({ok:true});
 });
});

app.patch("/api/profile",auth,async(req,res)=>{
 const name=String(
  req.body.name||""
 ).trim();

 const theme=req.body.theme;

 if(name){
  req.user.name=name.slice(0,50);
 }

 if(["light","dark"].includes(theme)){
  req.user.theme=theme;
 }

 await save();

 res.json({
  ok:true,
  user:safeUser(req.user)
 });
});

app.get("/api/my-orders",auth,(req,res)=>{
 res.json(
  db.orders
   .filter(
    o=>String(o.userId)===
    String(req.user.id)
   )
   .sort((a,b)=>b.id-a.id)
 );
});
app.get("/api/rewards",auth,(req,res)=>{
 const count=db.orders.filter(
  o=>String(o.userId)===String(req.user.id)
 ).length;

 res.json([
  {
   title:"Перше замовлення",
   done:count>=1
  },
  {
   title:"3 замовлення",
   done:count>=3
  },
  {
   title:"5 замовлень",
   done:count>=5
  }
 ]);
});

app.post("/api/promo/use",auth,async(req,res)=>{
 const code=String(req.body.code||"")
  .trim()
  .toUpperCase();

 if(!code){
  return res.status(400).json({
   error:"Введіть промокод"
  });
 }

 const promo=db.promos.find(
  p=>
   String(p.code).toUpperCase()===code
   &&
   p.active!==false
 );

 if(!promo){
  return res.status(404).json({
   error:"Промокод не знайдено"
  });
 }

 req.user.usedPromos ||= [];

 if(req.user.usedPromos.includes(code)){
  return res.status(400).json({
   error:"Ви вже використовували цей промокод"
  });
 }

 req.user.usedPromos.push(code);
 await save();

 res.json({
  ok:true,
  promo
 });
});

app.post("/api/orders",auth,async(req,res)=>{
 try{
  const items=Array.isArray(req.body.items)
   ? req.body.items
   : [];

  if(!items.length){
   return res.status(400).json({
    error:"Кошик порожній"
   });
  }

  const total=items.reduce(
   (sum,item)=>
    sum+
    Number(item.price||0)*
    Number(item.qty||1),
   0
  );

  const order={
   id:Date.now(),
   userId:req.user.id,
   username:req.user.username,
   name:req.user.name||req.user.username,
   phone:req.user.phone||"",
   items,
   total,
   status:"Нове",
   created:new Date().toISOString()
  };

  db.orders.push(order);
  await save();

  res.json({
   ok:true,
   order
  });

 }catch(e){
  console.error(e);

  res.status(500).json({
   error:"Не вдалося створити замовлення"
  });
 }
});

app.get("/api/admin/stats",admin,(req,res)=>{
 res.json({
  users:db.users.length,
  products:db.products.length,
  orders:db.orders.length,
  promos:db.promos.length
 });
});

app.get("/api/admin/users",admin,(req,res)=>{
 res.json(
  db.users.map(safeUser)
 );
});

app.get("/api/admin/orders",admin,(req,res)=>{
 res.json(
  [...db.orders].sort(
   (a,b)=>b.id-a.id
  )
 );
});

app.patch(
 "/api/admin/orders/:id",
 admin,
 async(req,res)=>{
  const order=db.orders.find(
   o=>String(o.id)===String(req.params.id)
  );

  if(!order){
   return res.status(404).json({
    error:"Замовлення не знайдено"
   });
  }

  if(req.body.status){
   order.status=String(req.body.status);
  }

  await save();

  res.json({
   ok:true,
   order
  });
 }
);

app.delete(
 "/api/admin/orders/:id",
 admin,
 async(req,res)=>{
  const before=db.orders.length;

  db.orders=db.orders.filter(
   o=>String(o.id)!==String(req.params.id)
  );

  if(before===db.orders.length){
   return res.status(404).json({
    error:"Замовлення не знайдено"
   });
  }

  await save();

  res.json({ok:true});
 }
);

app.post(
 "/api/admin/products",
 admin,
 upload.single("image"),
 async(req,res)=>{
  const name=String(req.body.name||"").trim();
  const price=Number(req.body.price||0);
  const desc=String(req.body.desc||"").trim();

  if(!name){
   return res.status(400).json({
    error:"Вкажіть назву товару"
   });
  }

  const product={
   id:Date.now(),
   name,
   price,
   desc,
   image:img(req.file)
  };

  db.products.push(product);
  await save();

  res.json({
   ok:true,
   product
  });
 }
);

app.patch(
 "/api/admin/products/:id",
 admin,
 upload.single("image"),
 async(req,res)=>{
  const product=db.products.find(
   p=>String(p.id)===String(req.params.id)
  );

  if(!product){
   return res.status(404).json({
    error:"Товар не знайдено"
   });
  }

  if(req.body.name!==undefined){
   product.name=String(req.body.name).trim();
  }

  if(req.body.price!==undefined){
   product.price=Number(req.body.price);
  }

  if(req.body.desc!==undefined){
   product.desc=String(req.body.desc);
  }

  if(req.file){
   product.image=img(req.file);
  }

  await save();

  res.json({
   ok:true,
   product
  });
 }
);

app.delete(
 "/api/admin/products/:id",
 admin,
 async(req,res)=>{
  const before=db.products.length;

  db.products=db.products.filter(
   p=>String(p.id)!==String(req.params.id)
  );

  if(before===db.products.length){
   return res.status(404).json({
    error:"Товар не знайдено"
   });
  }

  await save();

  res.json({ok:true});
 }
);

app.get("/api/admin/promos",admin,(req,res)=>{
 res.json(db.promos);
});

app.post("/api/admin/promos",admin,async(req,res)=>{
 const code=String(req.body.code||"")
  .trim()
  .toUpperCase();

 if(!code){
  return res.status(400).json({
   error:"Вкажіть промокод"
  });
 }

 if(
  db.promos.some(
   p=>String(p.code).toUpperCase()===code
  )
 ){
  return res.status(400).json({
   error:"Такий промокод уже існує"
  });
 }

 const promo={
  id:Date.now(),
  code,
  discount:Number(req.body.discount||0),
  active:true
 };

 db.promos.push(promo);
 await save();

 res.json({
  ok:true,
  promo
 });
});

app.delete(
 "/api/admin/promos/:id",
 admin,
 async(req,res)=>{
  db.promos=db.promos.filter(
   p=>String(p.id)!==String(req.params.id)
  );

  await save();

  res.json({ok:true});
 }
);

app.patch(
 "/api/admin/settings",
 admin,
 async(req,res)=>{
  db.settings={
   ...db.settings,
   ...req.body
  };

  await save();

  res.json({
   ok:true,
   settings:db.settings
  });
 }
);

app.patch(
 "/api/admin/users/:id",
 admin,
 async(req,res)=>{
  const user=db.users.find(
   u=>String(u.id)===String(req.params.id)
  );

  if(!user){
   return res.status(404).json({
    error:"Користувача не знайдено"
   });
  }

  if(
   req.body.role &&
   ["user","admin"].includes(req.body.role)
  ){
   if(user.role==="owner"){
    return res.status(400).json({
     error:"Роль власника змінити не можна"
    });
   }

   user.role=req.body.role;
  }

  await save();

  res.json({
   ok:true,
   user:safeUser(user)
  });
 }
);

app.use("/api",(req,res)=>{
 res.status(404).json({
  error:"API маршрут не знайдено",
  path:req.originalUrl
 });
});

app.use((err,req,res,next)=>{
 console.error("SERVER ERROR:",err);

 res.status(500).json({
  error:err.message||"Помилка сервера"
 });
});

load()
 .then(()=>{
  app.listen(PORT,()=>{
   console.log(
    `SYSTR server started on port ${PORT}`
   );
  });
 })
 .catch(err=>{
  console.error(
   "SERVER START ERROR:",
   err
  );

  process.exit(1);
 });
