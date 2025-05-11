const mongoose = require('mongoose');

const estudianteSchema = new mongoose.Schema({
  nombre: String,
  carrera: String,
  edad: Number
});

module.exports = mongoose.model('Estudiante', estudianteSchema);
