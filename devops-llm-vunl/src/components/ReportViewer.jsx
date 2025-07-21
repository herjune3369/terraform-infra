import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

function ReportViewer() {
  const { id } = useParams();
  const [items, setItems] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchReport() {
      setLoading(true);
      const res = await fetch(`/api/vuln/report/${id}`);
      if (res.ok) {
        const data = await res.json();
        setItems(data);
      } else {
        setItems(null);
      }
      setLoading(false);
    }
    fetchReport();
  }, [id]);

  if (loading) return <div>로딩 중...</div>;
  if (!items) return <div>보고서를 찾을 수 없습니다.</div>;

  return (
    <div>
      <h2>취약점 분석 보고서</h2>
      {items.length === 0 && <div>취약점이 없습니다.</div>}
      {items.map((item, idx) => (
        <div key={idx} style={{ border: '1px solid #ccc', margin: 16, padding: 16 }}>
          <h3>{item.type} ({item.vuln_id})</h3>
          <div><b>위험성:</b> {item.risk}</div>
          <div>
            <b>유사 사고 사례:</b>
            <ul>
              {item.incidents && item.incidents.map((inc, i) => (
                <li key={i}>
                  <b>{inc.title}</b> ({inc.date}): {inc.summary}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <b>대응 방안:</b>
            <ul>
              {item.management && Object.entries(item.management).map(([k, v]) => (
                <li key={k}><b>{k}</b>: {v}</li>
              ))}
            </ul>
          </div>
          <div><b>메타인지 교육:</b> {item.metacognition}</div>
        </div>
      ))}
    </div>
  );
}

export default ReportViewer; 