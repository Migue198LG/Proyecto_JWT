const jwt = require('jsonwebtoken');


function verificarToken(req, res, next){
    const token = req.headers['authorization'];
    if(!token){
        console.warn('Token no proporcionado');
        return res.status(403).send('Token requerido');
    }

    //ahora verificamos
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if(err){
            console.warn('Token invalido', err);
            return res.status(401).send('Token Invalido', err);
        }
        req.user = decoded;
        next();
    });
}

module.exports = verificarToken;