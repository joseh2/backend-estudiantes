const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.registrar = async (req, res) => {
  try {
    const { correo, contraseña } = req.body;

    if (!correo || !contraseña) {
      return res.status(400).json({ error: 'Correo y contraseña son requeridos' });
    }

    const hash = await bcrypt.hash(contraseña, 10);
    const usuario = new Usuario({ correo, contraseña: hash });
    await usuario.save();

    res.status(201).send('Usuario creado');
  } catch (error) {
    console.error('Error en el registro:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
};

exports.login = async (req, res) => {
  try {
    const { correo, contraseña } = req.body;

    if (!correo || !contraseña) {
      return res.status(400).json({ error: 'Correo y contraseña son requeridos' });
    }

    const usuario = await Usuario.findOne({ correo });
    if (!usuario) {
      return res.status(401).send('Credenciales inválidas');
    }

    const match = await bcrypt.compare(contraseña, usuario.contraseña);
    if (!match) {
      return res.status(401).send('Credenciales inválidas');
    }

    const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
};
