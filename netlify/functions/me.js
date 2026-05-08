// /.netlify/functions/me  (proxied as /api/me)
// Returns the currently authenticated Netlify Identity user (if any),
// trimmed to the fields the frontend needs for role-based UI.

const ROLE_RANK = { student: 0, teacher: 1, admin: 2, superuser: 3 };
const ROLE_LABELS = {
  student: 'Student',
  teacher: 'Teacher',
  admin: 'Administrator',
  superuser: 'Super User',
};

function highestRole(rolesArr) {
  const roles = Array.isArray(rolesArr) ? rolesArr : [];
  if (roles.length === 0) return 'student';
  return roles.reduce(
    (best, r) =>
      (ROLE_RANK[r] ?? -1) > (ROLE_RANK[best] ?? -1) ? r : best,
    'student'
  );
}

exports.handler = async (event, context) => {
  const headers = { 'Content-Type': 'application/json' };
  const user = context.clientContext && context.clientContext.user;

  if (!user) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ authenticated: false }),
    };
  }

  const role = highestRole(user.app_metadata && user.app_metadata.roles);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      authenticated: true,
      user: {
        id: user.sub,
        email: user.email,
        full_name:
          (user.user_metadata && user.user_metadata.full_name) || user.email,
        role,
        role_label: ROLE_LABELS[role] || role,
        can_manage_users: role === 'admin' || role === 'superuser',
      },
    }),
  };
};
