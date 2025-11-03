import { sleep } from "k6";
import http from "k6/http";

export const options = {
  vus: 50, // concurrent virtual users
  iterations: 1000,
};

const BASE = "...";
// username and password length shouldnt really matter but might as well make them long I guess
const PASSWORD =
  "super_secure_long_password_for_testing_argon2_hashing_performance_with_special_chars_!@#$%^&*()_+-=[]{}|;:,.<>?~";

function makeUsername() {
  return `test_user_${__VU}_${__ITER}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export default function() {
  const username = makeUsername();
  const payload = JSON.stringify({ username, password: PASSWORD });
  const params = { headers: { "Content-Type": "application/json" } };

  http.post(`${BASE}/create`, payload, params);
  sleep(0.1);

  http.post(`${BASE}/verify`, payload, params);
  sleep(0.05);
}
