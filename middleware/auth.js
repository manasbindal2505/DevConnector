const jwt   =   require('jsonwebtoken');
const config=   require('config');

module.exports = function(req,res,next){
    // Get the token
    const token = req.header('x-auth-token');

    if(!token){
        return res.status(401).json({msg:"No token, Authorization denied"})
    }

    try{
        const decoder   = jwt.verify(token,config.get('jwtSecret'));

        req.user    =   decoder.user;
        next();
    }catch(err){
        return res.status(401).json({msg:"Token is not valid"})
    }
}