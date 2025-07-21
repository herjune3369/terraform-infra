import React, { useState } from 'react';
import { Link } from 'react-router-dom';

function VulnUploader() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reportId, setReportId] = useState('');

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch('/api/vuln/analyze', { method: 'POST', body: form });
      const data = await res.json();
      setReportId(data.reportId);
    } catch (err) {
      alert('분석 중 오류가 발생했습니다.');
    }
    setLoading(false);
  };

  return (
    <div>
      <h2>웹 취약점 진단 이미지 업로드</h2>
      <form onSubmit={handleSubmit}>
        <input type="file" accept="image/*" onChange={handleFileChange} />
        <button type="submit" disabled={loading || !file}>분석 시작</button>
      </form>
      {loading && <div>분석 중... (스피너)</div>}
      {reportId && (
        <div>
          <Link to={`/reports/${reportId}`}>보고서 보기</Link>
        </div>
      )}
    </div>
  );
}

export default VulnUploader; 