const mysql = require('mysql2');
require('dotenv').config();
const express = require('express');
const cors = require('cors');

//crear una conexion con la base de datos

const db = mysql.createConnection({
    host : process.env.BD_HOST,
    user : process.env.BD_USER,
    password : process.env.BD_PASSWORD,
    database : process.env.BD_NAME
});

//vamos a verificar que se conecte
db.connect(err => {
    if(err) throw err;
    console.log("Conectado a la BD en MYSQL");
    console.log("host : " , process.env.BD_HOST);
    console.log("user : " , process.env.BD_NAME);
    console.log("password : " , process.env.BD_PASSWORD);
    console.log("name : " , process.env.BD_NAME);
});

module.exports = db;