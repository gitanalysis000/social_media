//jshint esversion:6
require('dotenv').config();
const bodyParser = require('body-parser');
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session= require('express-session');
const passport = require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false,
}))

app.use(passport.initialize());
app.use(passport.session()); 

//PA7L5RU43WsKSrOn
mongoose.set('strictQuery', false);
mongoose.connect(process.env.DATABASE_URL);

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    name:String,
    secret:String,
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User=  mongoose.model('User',userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id); 
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
   
    User.findOrCreate({ googleId: profile.id },{name:profile.displayName}, function (err, user) {
        
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FB_ID,
    clientSecret: process.env.FB_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



  

app.get('/',function(req,res){
    res.render('home');
})

app.get('/login',function(req,res){
    res.render('login');
})

app.get('/register',function(req,res){
    res.render('register');
})

app.get('/secrets',function(req,res){
if(req.isAuthenticated()){
    User.find({"secret":{$ne:null}},function(err,user){
        res.render('secrets',{userWithSecret:user});
    })
    

}
else{
   
    res.redirect('/login');
}
})
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/submit', function(req, res) {
    if(req.isAuthenticated()){
        res.render('submit');
    }
    else{
        res.redirect('/login');
    }
})

app.post('/submit', function(req, res) {
   
User.findById(req.user._id,function(err, user) {
    if(err){
        console.log(err);
    }
    else{
        user.secret=req.body.secret;
        user.save();
        res.redirect('/secrets');
    }

})
})

app.get('/logout',function(req,res){
    req.logout(function(err) {
        if (err) { console.log(err) }
        else
        res.redirect('/');
      });
}); 

app.post('/register',function(req,res){
User.register( {username:req.body.username,name:req.body.name},req.body.password,function(err,user){
    if(err){
        console.log(err);
        res.redirect('/register');
    }
    else{
        passport.authenticate("local")(req,res,function(){
            res.redirect('/secrets');
        })
    }
})
})

app.post('/login', function(req, res){
   const user=new User({
    username: req.body.username,
    password: req.body.password
   })
   
    req.login(user, function(err) {
        if (err) { console.log(err); }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');
            })
        } 
      });

})



app.listen(process.env.PORT,function(){
    console.log("Server listening on port 3000");
})