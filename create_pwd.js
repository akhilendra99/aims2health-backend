const bcrypt = require('bcryptjs');

let tryPwd = "admin12@aims2@health"

function generatePwdHash(){
    bcrypt.hash(tryPwd, 11)
    .then(hash => {
        console.log("raw pwd: ", tryPwd);
        console.log("hash: ", hash);
        
    })
    .catch( err =>{
    console.log("error:", err);
    });
}

generatePwdHash(tryPwd);
