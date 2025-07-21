import { BrowserRouter, Routes, Route } from 'react-router-dom';
import VulnUploader from './components/VulnUploader';
import ReportViewer from './components/ReportViewer';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<VulnUploader />} />
        <Route path="/reports/:id" element={<ReportViewer />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App; 