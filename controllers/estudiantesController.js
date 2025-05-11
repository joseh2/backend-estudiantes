const Estudiante = require('../models/Estudiante');

exports.listar = async (req, res) => {
  const lista = await Estudiante.find();
  res.json(lista);
};

exports.crear = async (req, res) => {
  const estudiante = new Estudiante(req.body);
  await estudiante.save();
  res.status(201).json(estudiante);
};
