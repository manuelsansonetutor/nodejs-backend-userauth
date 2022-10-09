const User = require("../database/models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports.signup = async (req, res) => {
  let { email, password } = req.body;

  try {
    //se la password è minore di 8 caratteri
    if (password.length < 8) {
      throw new Error("La password deve essere almeno di 8 caratteri");
    }

    //controllo se esiste un utente con la mail passata nella post
    let user = await User.findOne({ email: email });
    if (user) {
      //se esiste
      throw new Error("Esiste già un utente con questa email");
    } else {
      //a questo punto posso cifrare la password
      password = await bcrypt.hash(password, 12);
      let userData = new User({ email: email, password: password });

      //Salvo utente su db
      await userData.save();

      //rispondo al client con il messaggio di corretta iscrizione
      res.send({ status: 200, message: "Iscritto correttamente", body: {} });
    }
  } catch (error) {
    //qualunque eccezione risponde al client con il messaggio lanciato
    res.send({ status: 400, message: error.message, body: {} });
  }
};

module.exports.login = async (req, res) => {
  let { email, password } = req.body;

  try {
    //Verifico che esista un utente con la mail usata sul frontend
    let user = await User.findOne({ email: email });
    if (!user) {
      //se non esiste rispondo con un errore
      throw new Error("Mi dispiace non esiste un utente con questa email");
    } else {
      //se esiste, controllo che la password sia corretta
      let isCorrect = await bcrypt.compare(password, user.password);
      if (!isCorrect) {
        throw new Error("La password inserita non è corretta");
      } else {
        const token = await jwt.sign(
          { email: user.email },
          process.env.SECRET_KEY,
          { expiresIn: "1d" }
        );

        res.send({
          status: 200,
          message: "Login effettuato correttamente",
          body: token,
        });
      }
    }
  } catch (error) {
    res.send({ status: 400, message: error.message, body: {} });
  }
};
