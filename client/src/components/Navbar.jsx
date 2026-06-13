import { useContext } from 'react';
import { Link } from 'react-router-dom';
import { AuthContext } from '../utils/AuthContext';

export default function Navbar() {
  const { user, logout } = useContext(AuthContext);

  return (
    <nav className="bg-indigo-600 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link to="/" className="text-2xl font-bold">
              VulnSight
            </Link>
          </div>
          
          {user && (
            <div className="flex items-center space-x-4">
              <Link to="/dashboard" className="hover:text-indigo-200">
                Dashboard
              </Link>
              <span className="text-indigo-200">|</span>
              <span>{user.username}</span>
              <button
                onClick={logout}
                className="bg-indigo-700 hover:bg-indigo-800 px-4 py-2 rounded"
              >
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
