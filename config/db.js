
const pgpInit = require('pg-promise')
require('dotenv').config();


const pgp = pgpInit();


const db = pgp({
    host: process.env.DB_HOST,
    port: 5432, // default port for PostgreSQL
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    
})


module.exports = db;