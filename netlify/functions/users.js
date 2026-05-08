// /.netlify/functions/users  (proxied as /api/users[/:id])
// CRUD on Netlify Identity users. All role boundaries enforced server-side.
//
// Permissions:
//   superuser  -> can manage anyone (including other superusers/admins)
//   admin      -> can only manage teacher + student users
//   teacher    -> 403 forbidden
//   student    -> 403 forbidden
//
// User ID is passed as ?id=<uuid> for PUT/DELETE.

const ROLE_RANK = { student: 0, teacher: 1, admin: 2, superuser: 3 };
const ALL_ROLES = ['student', 'teacher', 'admin', 'superuser'];

function highestRole(rolesArr) {
  const roles = Array.isArray(rolesArr) ? rolesArr : [];
  if (roles.length === 0) return 'student';
  return roles.reduce(
    (best, r) => ((ROLE_RANK[r] ?? -1) > (ROLE_RANK[best] ?? -1) ? r : best),
    'student'
  );
}

function getUserRole(u) {
  return highestRole(u && u.app_metadata && u.app_metadata.roles);
}

function canManageRole(actorRole, targetRole) {
  if (actorRole === 'superuser') return true;
  if (actorRole === 'admin') return targetRole === 'teacher' || targetRole === 'student';
  return false;
}

function json(statusCode, body) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}

async function adminFetch(url, token, opts = {}) {
  return fetch(url, {
    ...opts,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
}

exports.handler = async (event, context) => {
  const { identity, user } = context.clientContext || {};

  if (!user) return json(401, { error: 'Authentication required' });
  if (!identity || !identity.token)
    return json(500, { error: 'Identity admin context unavailable' });

  const actorRole = getUserRole(user);
  if (actorRole !== 'admin' && actorRole !== 'superuser') {
    return json(403, { error: 'Insufficient permissions' });
  }

  const adminUrl = `${identity.url}/admin/users`;
  const params = event.queryStringParameters || {};
  const targetId = params.id;
  const method = event.httpMethod;

  try {
    // ---- LIST USERS ----
    if (method === 'GET' && !targetId) {
      const r = await adminFetch(adminUrl, identity.token);
      if (!r.ok) return json(r.status, { error: await r.text() });
      const data = await r.json();
      let users = data.users || data || [];

      // Admins only see teachers + students
      if (actorRole === 'admin') {
        users = users.filter(u => {
          const role = getUserRole(u);
          return role === 'teacher' || role === 'student';
        });
      }

      const trimmed = users.map(u => ({
        id: u.id,
        email: u.email,
        full_name: (u.user_metadata && u.user_metadata.full_name) || '',
        role: getUserRole(u),
        confirmed: !!u.confirmed_at,
        last_sign_in_at: u.last_sign_in_at,
        created_at: u.created_at,
      }));

      return json(200, { users: trimmed, actor_role: actorRole });
    }

    // ---- CREATE USER ----
    if (method === 'POST' && !targetId) {
      const body = JSON.parse(event.body || '{}');
      const { email, password, full_name, role } = body;

      if (!email || !password || !role)
        return json(400, { error: 'email, password, role are required' });
      if (!ALL_ROLES.includes(role))
        return json(400, { error: 'Invalid role' });
      if (password.length < 8)
        return json(400, { error: 'Password must be at least 8 characters' });
      if (!canManageRole(actorRole, role))
        return json(403, { error: `Your role cannot create ${role} users` });

      const r = await adminFetch(adminUrl, identity.token, {
        method: 'POST',
        body: JSON.stringify({
          email,
          password,
          confirm: true,
          user_metadata: { full_name: full_name || '' },
          app_metadata: { roles: [role] },
        }),
      });
      if (!r.ok) {
        const errText = await r.text();
        return json(r.status, { error: errText });
      }
      const data = await r.json();
      return json(201, { ok: true, id: data.id });
    }

    // ---- UPDATE / DELETE require an id ----
    if (!targetId)
      return json(400, { error: 'User id required (?id=<uuid>)' });

    // Fetch target user first to verify permissions and merge metadata
    const targetR = await adminFetch(`${adminUrl}/${targetId}`, identity.token);
    if (!targetR.ok)
      return json(targetR.status, { error: 'User not found' });
    const target = await targetR.json();
    const targetRole = getUserRole(target);

    if (target.id === user.sub)
      return json(400, { error: 'Cannot modify your own account here' });

    if (!canManageRole(actorRole, targetRole))
      return json(403, { error: `Cannot manage ${targetRole} users` });

    // ---- UPDATE USER ----
    if (method === 'PUT') {
      const body = JSON.parse(event.body || '{}');
      const updates = {};

      if (body.full_name !== undefined) {
        updates.user_metadata = {
          ...(target.user_metadata || {}),
          full_name: body.full_name,
        };
      }
      if (body.password) {
        if (body.password.length < 8)
          return json(400, { error: 'Password must be at least 8 characters' });
        updates.password = body.password;
      }
      if (body.role) {
        if (!ALL_ROLES.includes(body.role))
          return json(400, { error: 'Invalid role' });
        if (!canManageRole(actorRole, body.role))
          return json(403, { error: `Cannot promote to ${body.role}` });
        updates.app_metadata = {
          ...(target.app_metadata || {}),
          roles: [body.role],
        };
      }
      if (Object.keys(updates).length === 0)
        return json(400, { error: 'Nothing to update' });

      const r = await adminFetch(`${adminUrl}/${targetId}`, identity.token, {
        method: 'PUT',
        body: JSON.stringify(updates),
      });
      if (!r.ok) return json(r.status, { error: await r.text() });
      return json(200, { ok: true });
    }

    // ---- DELETE USER ----
    if (method === 'DELETE') {
      const r = await adminFetch(`${adminUrl}/${targetId}`, identity.token, {
        method: 'DELETE',
      });
      if (!r.ok) return json(r.status, { error: await r.text() });
      return json(200, { ok: true });
    }

    return json(405, { error: 'Method not allowed' });
  } catch (err) {
    console.error('users function error:', err);
    return json(500, { error: err.message || 'Server error' });
  }
};
