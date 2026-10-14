import React from 'react';
import {createRoot} from 'react-dom/client';
import {flushSync} from 'react-dom';
import OfficersPage from './pages/Officers.jsx';
import ReviewsPage from './pages/Reviews.jsx';
import AccountabilityPage from './pages/Accountability.jsx';
import initializeOfficers from './controllers/app.js';
import initializeReviews from './controllers/reviews.js';
import initializeAccountability from './controllers/accountability.js';
import {clearCharts} from './charts.jsx';

const page=document.documentElement.dataset.page||'officers';
const chosen=page==='reviews'?[ReviewsPage,initializeReviews]:page==='accountability'?[AccountabilityPage,initializeAccountability]:[OfficersPage,initializeOfficers];
const root=createRoot(document.getElementById('react-root'));
flushSync(()=>root.render(React.createElement(chosen[0])));
chosen[1]();
document.addEventListener('visibilitychange',()=>{if(document.hidden)clearCharts();});
window.addEventListener('pagehide',clearCharts);
