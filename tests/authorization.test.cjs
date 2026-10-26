const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const jwt = require('jsonwebtoken');
const express = require('express');
const root = path.resolve(__dirname, '..');
function load(relative, overrides = {}) {
  const filename = path.join(root, relative);
  const localRequire = createRequire(filename);
  const module = { exports: {} };
  const context = { module, exports: module.exports, require: id => Object.hasOwn(overrides, id) ? overrides[id] : localRequire(id), __dirname: path.dirname(filename), __filename: filename, process, Buffer, console: { log() {}, error() {}, warn() {} }, setTimeout, clearTimeout, URL };
  vm.runInNewContext('(function(exports,require,module,__filename,__dirname){'+fs.readFileSync(filename,'utf8')+'\n})', context, {filename})(module.exports, context.require, module, filename, path.dirname(filename));
  return module.exports;
}
function sign(role, id=1, extra={}) {
  const payload = role === 'helper' ? { helper_id:id, email_id:`${role}${id}@test.invalid` } : { userId:id, email:`${role}${id}@test.invalid` };
  const key = { patient:'JWT_SECRET_PATIENT', helper:'JWT_SECRET_PATIENT', doctor:'JWT_SECRET_DOC', admin:'JWT_SECRET_ADMIN' }[role];
  return jwt.sign({...payload, role, ...extra},process.env[key],{expiresIn:'5m'});
}
async function serve(app, run) {
  const server = await new Promise(resolve => { const s=app.listen(0,'127.0.0.1',()=>resolve(s)); });
  const request = async (method, route, token, body, headers={}) => {
    if(['GET','HEAD'].includes(method))body=undefined;
    const multipart = body instanceof FormData;
    const res=await fetch(`http://127.0.0.1:${server.address().port}${route}`,{method,signal:AbortSignal.timeout(5000),headers:{...(token?{Authorization:`Bearer ${token}`} : {}), ...(body && !multipart?{'Content-Type':'application/json'}:{}),...headers},...(body?{body:multipart?body:JSON.stringify(body)}:{})});
    return {status:res.status, headers:res.headers, body:await res.text()};
  };
  try { await run(request); } finally { await new Promise(resolve=>server.close(resolve)); }
}

test('JWT roles, legacy domains, cookies, revocation, malformed and forged identity', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN', 'COOKIE_SECURE', 'COOKIE_DOMAIN'];
  const previous = keys.map(key => process.env[key]);
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));
  process.env.JWT_SECRET_PATIENT='test-patient-secret'; process.env.JWT_SECRET_DOC='test-doctor-secret'; process.env.JWT_SECRET_ADMIN='test-admin-secret';
  process.env.COOKIE_SECURE='true'; delete process.env.COOKIE_DOMAIN;
  const authenticate=load('middleware/authenticate.js',{'./token-blacklist':{isBlacklisted:token=>token==='revoked'}});
  const app=express(); app.use(require('cookie-parser')());
  for(const role of ['patient','helper','doctor','admin']) app.get('/'+role,authenticate([role]),(req,res)=>res.json(req.userData));
  await serve(app,async request=>{
    for(const role of ['patient','helper','doctor','admin']) {
      assert.equal((await request('GET','/'+role)).status,401);
      assert.equal((await request('GET','/'+role,sign(role))).status,200);
      for(const other of ['patient','helper','doctor','admin'].filter(r=>r!==role)) assert.equal((await request('GET','/'+role,sign(other))).status,403,`${other} -> ${role}`);
    }
    assert.equal((await request('GET','/patient','revoked')).status,401);
    assert.equal((await request('GET','/patient',undefined,undefined,{Cookie:'auth_token='+sign('patient')})).status,200);
    assert.equal((await request('GET','/patient','malformed')).status,401);
    assert.equal((await request('GET','/patient',jwt.sign({userId:1,role:'patient'},process.env.JWT_SECRET_PATIENT,{algorithm:'HS384'}))).status,401);
    assert.equal((await request('GET','/patient',jwt.sign({userId:1,role:'patient'},process.env.JWT_SECRET_PATIENT,{expiresIn:-1}))).status,401);
    assert.equal((await request('GET','/patient',sign('patient',1,{userId:undefined}))).status,401);
    for (const userId of [[1], {id:1}, -1, 0, '1 OR 1=1']) {
      assert.equal((await request('GET','/patient',sign('patient',1,{userId}))).status,401);
    }
    assert.equal((await request('GET','/admin',sign('patient',1,{role:'admin'}))).status,401);
    assert.equal((await request('GET','/patient',sign('patient',1,{helper_id:1}))).status,401);
    assert.equal((await request('GET','/patient',sign('patient',1,{role:undefined}))).status,200);
    process.env.JWT_SECRET_ADMIN=process.env.JWT_SECRET_PATIENT;
    assert.equal((await request('GET','/admin',sign('patient',1,{role:undefined}))).status,500);
    assert.equal((await request('GET','/admin',sign('patient'))).status,500);
    assert.equal((await request('GET','/admin',sign('admin'))).status,500);
    process.env.JWT_SECRET_ADMIN='test-admin-secret';
  });
});

test('authorization database failures and missing accounts fail closed', async t => {
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  keys.forEach((key, i) => process.env[key] = `fixture-signing-domain-${i}`);
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));
  let reached=false;
  const app=express();
  const broken=load('utils/authorization.js') (async()=>{throw Object.assign(new Error('fixture failure'),{code:'FIXTURE_FAILURE'});});
  const missing=load('utils/authorization.js') (async()=>[]);
  app.get('/broken',broken.guard(['patient']),(req,res)=>{reached=true;res.send('unexpected');});
  app.get('/missing',missing.guard(['patient']),(req,res)=>{reached=true;res.send('unexpected');});
  await serve(app,async request=>{
    assert.equal((await request('GET','/broken',sign('patient'))).status,500);
    assert.equal((await request('GET','/missing',sign('patient'))).status,401);
    assert.equal(reached,false);
  });
});

test('real routes and parameterized MySQL ownership queries using connection-local temporary fixtures', {skip:process.env.TEST_MYSQL!=='1' && process.env.npm_lifecycle_event!=='test:authorization:mysql'}, async t => {
  require('dotenv').config();
  const keys = ['JWT_SECRET_PATIENT', 'JWT_SECRET_DOC', 'JWT_SECRET_ADMIN'];
  const previous = keys.map(key => process.env[key]);
  keys.forEach((key, i) => process.env[key] = `mysql-fixture-signing-domain-${i}`);
  t.after(() => keys.forEach((key, i) => previous[i] === undefined ? delete process.env[key] : process.env[key] = previous[i]));
  const mysql=require('mysql2');
  const db=await mysql.createConnection({host:process.env.DBHOST,user:process.env.DBUSER,password:process.env.DBPWD,database:process.env.DBNAME}).promise();
  const fixtureName=`authz-fixture-${process.pid}.pdf`;
  const uploadPrefix=`authz-upload-${process.pid}-${Date.now()}`;
  const fixturePath=path.join(root,'images',fixtureName);
  let fixtureWritten=false;
  try {
    // Temporary tables shadow real tables only on this connection. Never insert
    // into, update or delete production/imported application records.
    const definitions={
      patient_details:'patient_id INT PRIMARY KEY, parent_id INT, helper_id INT, email_id VARCHAR(100), fname VARCHAR(50), lname VARCHAR(50), address VARCHAR(50), dob DATE, mobile_no VARCHAR(30), countryCode VARCHAR(10), mobile_secondary VARCHAR(30), medical_history TEXT, id_type VARCHAR(30), adhaar VARCHAR(30), gender VARCHAR(20), hashed_pwd VARCHAR(100), ehr_id VARCHAR(30)',
      doctor_details:'doctor_id INT PRIMARY KEY, email_id VARCHAR(100), fname VARCHAR(50), lname VARCHAR(50), doc_type VARCHAR(50), hashed_pwd VARCHAR(100), ehr_id VARCHAR(30), validated VARCHAR(1) DEFAULT 1',
      helper_details:'helper_id INT PRIMARY KEY, email_id VARCHAR(100), hashed_pwd VARCHAR(100)',
      admin_details:'admin_id INT PRIMARY KEY, email_id VARCHAR(100), hashed_pwd VARCHAR(100)',
      patient_additional:'patient_id INT PRIMARY KEY, patient_consent INT, email_verification INT, phone_verification INT',
      patient_med_reports:'report_id INT PRIMARY KEY AUTO_INCREMENT, patient_id INT, report_title VARCHAR(100), content TEXT, imagePath VARCHAR(300), mediaType VARCHAR(30), recordDate DATE, mediaSize INT',
      doctor_calendar:'calendar_id INT PRIMARY KEY, doctor_id INT, patient_count INT, date DATE, time VARCHAR(20), fees INT, amt_paid_to_doc INT, doc_type VARCHAR(50) DEFAULT \'general\'',
      appointments:'appointment_id INT PRIMARY KEY, patient_id INT, calendar_id INT, date DATE, status INT, time VARCHAR(20), doc_type VARCHAR(50)',
      prescriptions:'patient_id INT, calendar_id INT, report_title VARCHAR(100), content TEXT, filePath VARCHAR(300)',
      doctor_additional:'doctor_id INT PRIMARY KEY, bio_data_url VARCHAR(300), bank_ifsc VARCHAR(30), bank_ac_no VARCHAR(30), bank_ac_name VARCHAR(30)'
    };
    for(const [table,definition] of Object.entries(definitions)) await db.query(`CREATE TEMPORARY TABLE ${table} (${definition})`);
    for(const [id,parent,helper] of [[1,null,1],[2,null,2],[3,1,-1],[4,1,2]]) await db.query('INSERT INTO patient_details (patient_id,parent_id,helper_id,email_id,fname,lname) VALUES (?,?,?,?,?,?)',[id,parent,helper,`patient${id}@test.invalid`,'Test','Patient']);
    for(const role of ['doctor','helper','admin']) for(const id of [1,2]) await db.query(`INSERT INTO ${role}_details (${role}_id,email_id) VALUES (?,?)`,[id,`${role}${id}@test.invalid`]);
    await db.query("INSERT INTO doctor_calendar (calendar_id,doctor_id,patient_count,date,time,fees,amt_paid_to_doc) VALUES (11,1,1,'2026-01-01','1000',100,0),(22,2,1,'2026-01-01','1000',100,0),(33,1,0,'2026-01-01','1000',100,0)");
    await db.query("INSERT INTO appointments VALUES (101,1,11,'2026-01-01',0,'1000','general'),(202,2,22,'2026-01-01',0,'1000','general')");
    await db.query("INSERT INTO patient_med_reports (report_id,patient_id,report_title,imagePath) VALUES (1,1,'Own','/images/own.pdf'),(2,2,'Other','/images/other.pdf')");
    await db.query("INSERT INTO prescriptions VALUES (1,11,'Own prescription','fixture','/images/rx-own.pdf'),(2,22,'Other prescription','fixture','/images/rx-other.pdf')");
    await db.query("INSERT INTO doctor_additional (doctor_id) VALUES (1),(2)");
    await db.query("UPDATE doctor_additional SET bio_data_url = '/images/published-doctor-bio.pdf' WHERE doctor_id = 1");
    const passwordHash=await require('bcryptjs').hash('FixturePassword1!',4);
    for(const role of ['patient','doctor','helper','admin']) await db.query(`UPDATE ${role}_details SET hashed_pwd = ?`,[passwordHash]);
    fs.mkdirSync(path.dirname(fixturePath),{recursive:true});
    fs.writeFileSync(fixturePath,'authorization fixture',{flag:'wx'});fixtureWritten=true;
    await db.query('INSERT INTO patient_med_reports (report_id,patient_id,report_title,imagePath) VALUES (99,1,?,?)',['File fixture','/images/'+fixtureName]);
    const callback={connect:fn=>fn(null),query:(sql,values,fn)=>{ if(typeof values==='function'){fn=values;values=[];} db.query(sql,values).then(([rows])=>fn(null,rows,[]),fn); }};
    const ehr={connect:fn=>fn(null), query:async sql=>{if(sql==='SELECT 1')return [[{ok:1}]];throw Error('EHR side effect forbidden in tests');}};
    const routers={};
    const noExternal=()=>{throw Error('External side effect forbidden in tests');};
    for(const name of ['patients','doctors','patient_helpers','admin']) {
      let connection=0, pool=0;
      const fakeMysql={createConnection:()=>connection++===0?callback:ehr, createPool:()=>({promise:()=>pool++===0?db:ehr})};
      routers[name]=load('routes/'+name+'.js',{'mysql2':fakeMysql,'twilio':()=>({messages:{create:noExternal}}),'razorpay':function(){return {orders:{create:noExternal}};},'@sendgrid/mail':{setApiKey(){},send:noExternal},'axios':Object.assign(noExternal,{post:noExternal}),'../utils/zeptomail':{sendMail:noExternal},'needle':{post:noExternal}});
    }
    const app=express();app.use(express.json());app.use(require('cookie-parser')());
    const csrf=require('../middleware/csrf-protection');
    app.use(csrf.requireTrustedOrigin(['http://localhost:4200']));app.use(csrf.requireCsrfToken);
    app.use('/images',load('middleware/protected-files.js',{'mysql2':{createPool:()=>({promise:()=>db})}})());
    for(const [prefix,name] of [['patient','patients'],['doctor','doctors'],['helper','patient_helpers'],['admin','admin']])app.use('/api/'+prefix,routers[name]);
    const access=require('../utils/authorization')(async(sql,values)=>(await db.query(sql,values))[0]);
    app.get('/file/:name',access.guard(['patient','helper','doctor','admin'],(req,a)=>a.file(req.userData,req.params.name)),(req,res)=>res.send('authorized'));
    await serve(app,async request=>{
      // Exercise real login issuers. Keep existing distinct-secret enforcement;
      // roles are server-issued even if the frontend submits role:'admin'.
      for(const [prefix,role] of [['patient','patient'],['doctor','doctor'],['helper','helper'],['admin','admin']]) {
        const body=role==='helper'?{email_id:`${role}1@test.invalid`,password:'FixturePassword1!',role:'admin'}:{email:`${role}1@test.invalid`,password:'FixturePassword1!',role:'admin'};
        const login=await request('POST','/api/'+prefix+'/login',undefined,body);
        assert.equal(login.status,200,role+' login '+login.body);
        const loginBody=JSON.parse(login.body);
        const secret = process.env[{patient:'JWT_SECRET_PATIENT',helper:'JWT_SECRET_PATIENT',doctor:'JWT_SECRET_DOC',admin:'JWT_SECRET_ADMIN'}[role]];
        let issued;
        let patientCookie;
        let patientCsrf;
        if(role==='patient') {
          assert.equal(loginBody.token,undefined,'patient password login keeps the JWT out of JSON');
          assert.equal(loginBody.userId,1);
          assert.equal(loginBody.userEmail,'patient1@test.invalid');
          assert.equal(loginBody.userName,'Test Patient');
          const cookies=login.headers.getSetCookie();
          const authCookie=cookies.find(value=>value.startsWith('auth_token='));
          const csrfCookie=cookies.find(value=>value.startsWith('csrf_token='));
          assert.ok(authCookie,'patient login sets HttpOnly auth cookie');
          assert.ok(csrfCookie,'patient login sets CSRF cookie');
          assert.match(authCookie,/; HttpOnly/i);
          assert.match(authCookie,/; Secure/i);
          assert.match(authCookie,/; SameSite=Lax/i);
          assert.doesNotMatch(csrfCookie,/; HttpOnly/i);
          assert.match(csrfCookie,/; Secure/i);
          assert.match(csrfCookie,/; SameSite=Lax/i);
          issued=authCookie.match(/^auth_token=([^;]+)/)[1];
          patientCsrf=csrfCookie.match(/^csrf_token=([^;]+)/)[1];
          patientCookie='auth_token='+issued+'; csrf_token='+patientCsrf;
          assert.equal((await request('GET','/api/patient/get-patients?id=1',undefined,undefined,{Cookie:patientCookie})).status,200,'patient cookie authenticates patient API');
        } else {
          issued=loginBody.token;
        }
        assert.equal(jwt.verify(issued,secret).role,role);
        if(role!=='admin')assert.equal((await request('GET','/api/admin/listpatients',issued)).status,403);

        // A frontend can replay response JSON, but only the server-issued JWT
        // is accepted by protected middleware. A failed login issues no new
        // token/cookie and must not undo logout of the captured token.
        const wrongBody={...body,password:'WrongFixturePassword!'};
        const failed=await request('POST','/api/'+prefix+'/login',undefined,wrongBody);
        assert.equal(failed.status,401,role+' bad password');
        assert.equal(failed.headers.get('set-cookie'),null,role+' failed login must not set cookies');
        assert.equal((await request('GET','/api/patient/get-patients?id=1', 'response-replacement')).status,401,'replaced frontend response is not a credential');
        const logout=role==='patient'
          ? await request('POST','/api/'+prefix+'/logout',undefined,undefined,{Cookie:patientCookie,'x-csrf-token':patientCsrf})
          : await request('POST','/api/'+prefix+'/logout',issued);
        assert.equal(logout.status,200,role+' logout '+logout.body);
        assert.match(logout.headers.get('set-cookie')||'',/auth_token=;/,role+' logout clears auth cookie');
        assert.match(logout.headers.get('set-cookie')||'',/csrf_token=;/,role+' logout clears CSRF cookie');
        const probe={patient:'/api/patient/get-patients?id=1',doctor:'/api/doctor/appointment/1',helper:'/api/helper/get-patients',admin:'/api/admin/listpatients'}[role];
        assert.equal((await request('GET',probe,issued)).status,401,role+' old bearer token after logout');
        assert.equal((await request('GET',probe,undefined,undefined,{Cookie:'auth_token='+issued})).status,401,role+' old cookie after logout');
        const fresh=await request('POST','/api/'+prefix+'/login',undefined,body);
        assert.equal(fresh.status,200,role+' fresh login after logout');
        let freshToken=JSON.parse(fresh.body).token;
        if(role==='patient') {
          const freshAuthCookie=fresh.headers.getSetCookie().find(value=>value.startsWith('auth_token='));
          freshToken=freshAuthCookie.match(/^auth_token=([^;]+)/)[1];
        }
        assert.notEqual((await request('GET',probe,freshToken)).status,401,role+' fresh session is accepted');
      }
      const p=sign('patient'),p2=sign('patient',2),d=sign('doctor'),h=sign('helper'),a=sign('admin');
      const downloaded=await request('GET','/images/'+fixtureName,p);
      assert.equal(downloaded.status,200);assert.equal(downloaded.body,'authorization fixture');assert.equal(downloaded.headers.get('cache-control'),'private, no-store');
      assert.equal((await request('GET','/images/'+fixtureName,sign('patient',2))).status,404);
      assert.equal((await request('GET','/images/'+fixtureName)).status,401);
      assert.equal((await request('HEAD','/images/'+fixtureName,sign('patient',2))).status,404);
      assert.equal((await request('HEAD','/images/'+fixtureName,h)).status,200);
      const ranged = await request('GET','/images/'+fixtureName,d,undefined,{Range:'bytes=0-4'});
      assert.equal(ranged.status,206);assert.equal(ranged.body,'autho');
      assert.equal((await request('GET','/images/'+fixtureName,undefined,undefined,{Cookie:'auth_token='+p})).status,200);
      assert.equal((await request('GET','/images/'+fixtureName,sign('doctor',2))).status,404);
      assert.equal((await request('GET','/images/'+fixtureName,a)).status,200);
      assert.equal((await request('GET','/images/unmapped.pdf',a)).status,404);
      assert.equal((await request('POST','/images/'+fixtureName,p,{})).status,405);
      assert.equal((await request('GET','/images/a%2F'+fixtureName,p)).status,404);
      const uploaded = () => fs.readdirSync(path.join(root,'images')).filter(name => name.startsWith(uploadPrefix));
      for (const [route, token, fields] of [
        ['/api/helper/medreport',h,{patient_id:2}],
        ['/api/doctor/uploadprescription',d,{patientId:2,calendarId:22}],
        ['/api/patient/medreport/1',p,{id:2}],
      ]) {
        const form = new FormData();
        for (const [key,value] of Object.entries(fields)) form.set(key,String(value));
        form.set('image',new Blob(['fixture upload'],{type:'application/pdf'}),uploadPrefix+'.pdf');
        assert.equal((await request(route.includes('/medreport/1')?'PUT':'POST',route,token,form)).status,404);
      }
      // Policy denial removes files Multer wrote before it could parse IDs.
      for (let attempt=0; uploaded().length && attempt<20; attempt++) await new Promise(resolve=>setTimeout(resolve,10));
      assert.deepEqual(uploaded(),[]);
      const ownUpload = new FormData();
      ownUpload.set('patient_id','1');ownUpload.set('title','Authorized multipart report');
      ownUpload.set('image',new Blob(['fixture upload'],{type:'application/pdf'}),uploadPrefix+'.pdf');
      assert.equal((await request('POST','/api/helper/medreport',h,ownUpload)).status,201);
      assert.equal(uploaded().length,1);
      assert.equal((await request('GET','/images/'+uploaded()[0],p)).status,200);
      assert.equal((await request('GET','/images/'+uploaded()[0],p2)).status,404);
      assert.equal((await request('POST','/api/patient/listprescriptions',undefined,{patientId:1,calendarId:11},{Cookie:'auth_token='+p})).status,403);
      assert.equal((await request('POST','/api/patient/listprescriptions',undefined,{patientId:1,calendarId:11},{Cookie:'auth_token='+p+'; csrf_token=fixture','x-csrf-token':'fixture'})).status,200);
      assert.equal((await request('POST','/api/patient/listprescriptions',undefined,{patientId:1,calendarId:11},{Cookie:'auth_token='+p+'; csrf_token=fixture','x-csrf-token':'fixture',Origin:'https://untrusted.invalid'})).status,403);
      for(const method of ['POST','PUT','DELETE','PATCH'])assert.equal((await request(method,'/api/admin/listpatients',p,{})).status,404);
      for (const method of ['GET','PUT','DELETE','PATCH']) {
        assert.equal((await request(method,'/api/admin/login',p,{})).status,404);
        assert.equal((await request(method,'/api/doctor/login',p,{})).status,method==='GET'?403:404);
      }
      const publicRoutes={patients:new Set(['POST /contact','POST /patientExists','POST /signup','POST /login','POST /send-otp-login','POST /verify-otp-login','POST /forgetpwd','POST /forgetpwdresetpwd']),doctors:new Set(['POST /doctorExists','POST /signup','POST /login','POST /forgetpwd','POST /forgetpwdresetpwd']),admin:new Set(['POST /login','GET /getdoctorTypes','GET /listdoctorTypes','GET /listdoctorTypes/:date']),patient_helpers:new Set(['POST /register','POST /login','POST /sendPhoneVerifyOTP','POST /verifyPhoneOTP','POST /sendEmailVerifyOTP','POST /verifyEmailOTP','POST /forgetpwd'])};
      let protectedCount=0;
      for(const [name,router] of Object.entries(routers))for(const layer of router.stack.filter(layer=>layer.route))for(const method of Object.keys(layer.route.methods)) {
        const key=method.toUpperCase()+' '+layer.route.path;
        if(publicRoutes[name].has(key))continue;
        const prefix={patients:'patient',doctors:'doctor',admin:'admin',patient_helpers:'helper'}[name];
        const url='/api/'+prefix+layer.route.path.replace(/:[A-Za-z_]+/g,'1');
        const response=await request(method.toUpperCase(),url,undefined,{});
        assert.equal(response.status,401,'protected inventory '+key+' '+response.body);protectedCount++;
        const deniedRoles = name === 'admin' ? ['patient','doctor','helper'] : name === 'doctors' ? ['patient','helper'] : name === 'patient_helpers' ? ['patient','doctor'] : ['doctor'];
        for (const deniedRole of deniedRoles) {
          const denied = await request(method.toUpperCase(),url,sign(deniedRole),{});
          assert.equal(denied.status,403,`${deniedRole} denied ${prefix} ${key}: ${denied.body}`);
        }
      }
      t.diagnostic(`${protectedCount} protected route registrations reject unauthenticated access; all four login issuers, role separation, protected GET/HEAD downloads, method changes and cookie CSRF controls passed.`);
      const cases=[
        ['GET','/api/patient/medreports/2',p,undefined,404],['GET','/api/patient/medreports/1',p,undefined,200],
        ['GET','/api/patient/appointment/1',p,undefined,200],
        ['POST','/api/patient/search',p,{appmntDate:'2026-01-01',docType:'general'},201],
        ['POST','/api/helper/search',h,{appmntDate:'2026-01-01',docType:'general'},201],['GET','/api/patient/appointment/2',p,undefined,404],
        ['GET','/api/patient/appointment/3',p,undefined,200],['GET','/api/patient/appointment/4',p,undefined,404],
        ['GET','/api/patient/appointment/1',h,undefined,200],['GET','/api/patient/appointment/2',h,undefined,404],
        ['GET','/api/patient/getappointmentreceipt/1',h,undefined,200],['GET','/api/patient/getappointmentreceipt/2',h,undefined,404],
        ['GET','/api/patient/medreportlist/2',p,undefined,404],['GET','/api/patient/medreportlist/2',a,undefined,200],
        ['POST','/api/patient/2',p,{},404],['POST','/api/patient/1',p,{},200],
        ['GET','/api/patient/get-patients?id=2',p,undefined,404],['GET','/api/patient/get-patients?id=1',p,undefined,200],
        ['POST','/api/patient/listprescriptions',p,{patientId:2,calendarId:22},404],['POST','/api/patient/listprescriptions',h,{patientId:1,calendarId:11},200],
        ['POST','/api/patient/getorderid',p,{patient_id:2},404],['POST','/api/patient/setappointment',p,{patient_id:2},404],
        ['PUT','/api/patient/medreportwoimage/2',p,{id:2,title:'tampered'},404],
        ['PUT','/api/patient/medreportwoimage/1',p,{id:2,title:'tampered'},404],
        ['PUT','/api/patient/medreportwoimage/1',p,{id:1,image:'/images/other.pdf'},404],
        ['PUT','/api/patient/medreportwoimage/1',p,{id:1,title:'Updated',image:'/images/own.pdf'},201],
        ['DELETE','/api/patient/medrecords/2',p,undefined,404],
        ['GET','/api/doctor/appointment/2',d,undefined,404],['GET','/api/doctor/appointment/1',d,undefined,200],['GET','/api/doctor/appointment/2',a,undefined,200],
        ['GET','/api/doctor/2',d,undefined,404],['GET','/api/doctor/patientDetails/22',d,undefined,404],['GET','/api/doctor/patientDetails/11',d,undefined,200],
        ['GET','/api/doctor/medreportlist/2',d,undefined,404],['GET','/api/doctor/medreportlist/1',d,undefined,200],
        ['POST','/api/doctor/deleteAppointment',d,{caledarId:22},404],['POST','/api/doctor/deleteAppointment',d,{caledarId:33},201],
        ['POST','/api/doctor/updateAppointmentState',d,{appointmentId:202},404],['POST','/api/doctor/updateAppointmentState',d,{appointmentId:101},201],
        ['POST','/api/doctor/sendVSData',d,{patientId:2,docId:1},404],['POST','/api/doctor/sendSmsLink',d,{appointmentId:202},404],
        ['POST','/api/doctor/listprescriptions',d,{patientId:2,calendarId:22},404],['POST','/api/doctor/listprescriptions',d,{patientId:1,calendarId:11},201],
        ['POST','/api/doctor/uploadprescription',d,{patientId:1,calendarId:22},404],
        ['POST','/api/doctor/uploadprescription',d,{patientId:1,calendarId:11,title:'Authorized prescription'},201],
        ['POST','/api/patient/medreportwoimage',p,{patient_id:2,role:'admin',title:'Authorized own report',image:'na'},201],
        ['POST','/api/patient/medreportwoimage',p,{title:'Stolen link',image:'/images/other.pdf'},404],
        ['POST','/api/helper/medreport',h,{patient_id:1,title:'Authorized helper report'},201],
        ['POST','/api/patient/setappointment',p,{calendar_id:999,doctor_id:2,email_id:'patient2@test.invalid'},404],
        ['GET','/api/patient/appointment/2%20OR%201=1',p,undefined,404],
        ['GET','/api/patient/appointment/1',sign('patient',1,{email:'patient2@test.invalid'}),undefined,401],
        ['POST','/api/admin/updateAcNo',p,{doctor_id:1,role:'admin',permission:'all',updatedValue:'tampered'},403],
        ['GET','/api/helper/medreports/2',h,undefined,404],['GET','/api/helper/medreports/1',h,undefined,200],
        ['GET','/api/helper/medreports/2/2',h,undefined,404],['GET','/api/helper/medreports/1/1',h,undefined,200],
        ['PUT','/api/helper/medreport/2/2',h,{title:'tampered'},404],['PUT','/api/helper/medreport/1/1',h,{title:'Helper update'},200],
        ['POST','/api/helper/update-consent',h,{patient_id:2},404],['POST','/api/helper/medreport',h,{patient_id:2,title:'tampered'},404],
        ['DELETE','/api/helper/medrecords/2',h,undefined,404],
        ['POST','/api/helper/mis-info',h,{doctor_id:1,from_date:'2026-01-01',to_date:'2026-02-01'},403],
        ['POST','/api/helper/mis-info',a,{doctor_id:1,from_date:'2026-01-01',to_date:'2026-02-01'},200],
        ['GET','/api/admin/listpatients',p,undefined,403],['POST','/api/admin/validatedoc',p,{email_id:'doctor1@test.invalid'},403],
        ['GET','/api/admin/listpatients',a,undefined,201],
        ['POST','/api/admin/updateAcNo',a,{doctor_id:2,updatedValue:'authorized'},200],
        ['GET','/file/own.pdf',p,undefined,200],['GET','/file/other.pdf',p,undefined,404],['GET','/file/own.pdf',h,undefined,200],['GET','/file/other.pdf',h,undefined,404],
        ['GET','/file/rx-own.pdf',d,undefined,200],['GET','/file/rx-other.pdf',d,undefined,404],['GET','/file/other.pdf',a,undefined,200],['GET','/file/unmapped.pdf',a,undefined,404],
        ['GET','/file/published-doctor-bio.pdf',p,undefined,200],['GET','/file/published-doctor-bio.pdf',h,undefined,200],
        ['GET','/file/published-doctor-bio.pdf',d,undefined,200],['GET','/file/published-doctor-bio.pdf',sign('doctor',2),undefined,404],
        ['DELETE','/api/patient/medrecords/2',p2,undefined,200],['DELETE','/api/helper/medrecords/1',h,undefined,200]
      ];
      // Verify each operation also rejects unauthenticated callers before SQL or side effects.
      const seen=new Set();
      for(const [method,url,token,body,expected] of cases) {
        const key=method+' '+url;
        if(!seen.has(key)){const unauth=await request(method,url,undefined,body);assert.equal(unauth.status,401,'unauthenticated '+key+' '+unauth.body);seen.add(key);}
        if(method==='DELETE' && url==='/api/patient/medrecords/2' && token===p2){
          const [[untouched]]=await db.query('SELECT report_title FROM patient_med_reports WHERE report_id=2');assert.equal(untouched.report_title,'Other');
        }
        const response=await request(method,url,token,body);
        assert.equal(response.status,expected,key+' '+response.body);
      }
      const family=JSON.parse((await request('GET','/api/patient/get-patients?id=1',p)).body);assert.deepEqual(family.patients.map(row=>row.patient_id),[3]);assert.equal(Object.hasOwn(family.patients[0],'hashed_pwd'),false);
      for(const prefix of ['patient','helper']){
        const search=JSON.parse((await request('POST','/api/'+prefix+'/search',prefix==='patient'?p:h,{appmntDate:'2026-01-01',docType:'general'})).body);
        assert.equal(Object.hasOwn(search.searchedResults[0],'hashed_pwd'),false);assert.equal(Object.hasOwn(search.searchedResults[0],'bank_ac_no'),false);
      }
      const clinician=JSON.parse((await request('GET','/api/doctor/patientDetails/11',d)).body);assert.equal(Object.hasOwn(clinician[0],'hashed_pwd'),false);
      const [[account]]=await db.query('SELECT bank_ac_no FROM doctor_additional WHERE doctor_id=2');assert.equal(account.bank_ac_no,'authorized');
      const [[created]]=await db.query("SELECT patient_id FROM patient_med_reports WHERE report_title='Authorized own report'");assert.equal(created.patient_id,1);
      const [[helperCreated]]=await db.query("SELECT patient_id FROM patient_med_reports WHERE report_title='Authorized helper report'");assert.equal(helperCreated.patient_id,1);
      const [[rx]]=await db.query("SELECT patient_id,calendar_id FROM prescriptions WHERE report_title='Authorized prescription'");assert.equal(rx.patient_id,1);assert.equal(rx.calendar_id,11);
      const [[other]]=await db.query('SELECT status FROM appointments WHERE appointment_id=202');assert.equal(other.status,0);
      const [[own]]=await db.query('SELECT status FROM appointments WHERE appointment_id=101');assert.equal(own.status,1);
      const [[otherCalendar]]=await db.query('SELECT COUNT(*) AS n FROM doctor_calendar WHERE calendar_id=22');assert.equal(otherCalendar.n,1);
      const [[deletedOwn]]=await db.query('SELECT COUNT(*) AS n FROM doctor_calendar WHERE calendar_id=33');assert.equal(deletedOwn.n,0);
      await db.query('UPDATE doctor_details SET validated = 0 WHERE doctor_id = 1');
      assert.equal((await request('GET','/api/doctor/appointment/1',d)).status,401);
      assert.equal((await request('GET','/file/published-doctor-bio.pdf',p)).status,404);
      await db.query('UPDATE doctor_details SET validated = 1 WHERE doctor_id = 1');
      assert.equal((await request('GET','/api/doctor/appointment/1',d)).status,200);
      t.diagnostic(`${cases.length} positive/negative route cases plus ${seen.size} unauthenticated method/path checks; temporary-table mutation assertions passed.`);
    });
  } finally {
    if(fixtureWritten)fs.unlinkSync(fixturePath);
    for (const name of fs.readdirSync(path.join(root,'images')).filter(name => name.startsWith(uploadPrefix))) fs.unlinkSync(path.join(root,'images',name));
    await db.end();
  }
});
