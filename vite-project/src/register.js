import React, { useState } from 'react';
import { useRegisterMutation } from '../app/api';

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [register] = useRegisterMutation();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await register({ username, password }).unwrap();
      alert('Регистрация успешна!');
    } catch (err) {
      alert('Ошибка регистрации');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Логин"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        placeholder="Пароль"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit">Зарегистрироваться</button>
    </form>
  );
};

export default Register;