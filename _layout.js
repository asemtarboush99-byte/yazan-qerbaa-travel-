// دالة التعامل مع الـ API
async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || 'حدث خطأ في الاتصال');
  }
  return data;
}

// دالة تسجيل الخروج الموحدة
async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST' });
  } catch (e) {
    console.error(e);
  } finally {
    // التوجيه فوراً لصفحة الدخول
    window.location.href = '/login.html';
  }
}

// تنسيق المبالغ المالية
function money(val) {
  return (Number(val) || 0).toFixed(2);
}