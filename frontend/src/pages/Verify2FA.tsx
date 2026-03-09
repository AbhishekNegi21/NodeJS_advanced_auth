import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { verify2FA } from "../api/authApi";
import { setAccessToken } from "../api/fetchClient";

const Verify2FA = () => {
  const { state } = useLocation();
  const navigate = useNavigate();
  const { setUser } = useAuth(); // we will add this to context

  const [code, setCode] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const data = await verify2FA(state.userId, code);

    setAccessToken(data.accessToken);
    setUser(data.user);

    navigate("/dashboard");
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Enter 2FA Code</h2>

      <input
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="123456"
      />

      <button type="submit">Verify</button>
    </form>
  );
};

export default Verify2FA;
