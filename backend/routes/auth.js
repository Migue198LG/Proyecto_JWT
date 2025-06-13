const express = require('express')
const router = express.Router();
const bvrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../bd');


//ruta para el registro
router.post('/register', async(req, res) => {
    const {email, password} = req.body;
    try{
        //aqui es donde es importante recordar que para el campo de pass hay que hasheado
        const hashed = await bvrypt.hash(password, 10);
        db.query('INSERT INTO usuarios (email, password) VALUES (? , ?)', [email, hashed], (err, result) => {
            if(err){
                console.log('Error al registrar al usuario', err);
                return res.status(500).send('Error al registrar');
                //res.send(pagina o al mensaje)
            }
            //debugg
            console.log("Usuario registrado con el ID", result.insertId);
            res.status(200).send('Usuario Registrado');
        });
    } catch(error){
        console.log('Error en el servidor al momento de registrar {register}: ', error);
        res.status(500).send('Error interno del servidor');
    }
});

//ruta de login
router.post('/login', (req, res) => {
    const { email, password } = req.body; // ESTA LÍNEA FALTABA

    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, result) => {
        if (err) {
            console.log('Error en la consulta del login: ', err);
            return res.status(500).send('Error en el servidor');
        }

        if (result.length === 0) {
            console.log('Usuario no encontrado');
            return res.status(401).send('Credenciales inválidas');
        }

        const user = result[0];
        const valid = await require('bcryptjs').compare(password, user.password);
        if (!valid) {
            console.warn("Contraseña incorrecta para usuario:", email);
            return res.status(401).send('Contraseña incorrecta. Usuario no autorizado');
        }

        const token = require('jsonwebtoken').sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log('Token generado para el usuario:', user.email);
        res.json({ token });
    });
});

const verificarToken = require('../middleware/verifyToken');

router.get('/protected', verificarToken, (req, res) => {
    res.send(`Token válido. Bienvenido, ${req.user.email}`);
});

//cambio
module.exports = router