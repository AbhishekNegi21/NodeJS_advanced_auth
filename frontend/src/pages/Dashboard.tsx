import { useAuth } from "../hooks/useAuth";

const Dashboard = () => {
  const { user, logoutUser } = useAuth();

  if (!user) return null;

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center">
      <div className="bg-white p-8 rounded-lg shadow-md w-96 text-center">
        <h1 className="text-2xl font-bold mb-4">Welcome, {user.name} 👋</h1>

        <p className="mb-2">
          <strong>Email:</strong> {user.email}
        </p>

        <p className="mb-6">
          <strong>Role:</strong> {user.role}
        </p>

        <button
          onClick={logoutUser}
          className="w-full bg-red-600 text-white p-2 rounded hover:bg-red-700 transition"
        >
          Logout
        </button>
      </div>
    </div>
  );
};

export default Dashboard;
