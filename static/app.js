document.addEventListener('DOMContentLoaded', async () => {
  const setText = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  const showEmpty = (id, visible) => {
    const node = document.getElementById(id);
    if (node) node.style.display = visible ? 'grid' : 'none';
  };
  const showChartError = () => {
    document.querySelectorAll('.chart-empty').forEach(node => {
      node.textContent = 'Charts could not load. Check your internet connection or refresh the page.';
      node.style.display = 'grid';
    });
  };

  // A submitted scan is rendered directly below the scanner. Scroll there on the
  // response so the report is visible while the URL input remains just above it.
  const report = document.getElementById('scan-result');
  if (report) {
    requestAnimationFrame(() => report.scrollIntoView({behavior: 'smooth', block: 'start'}));
  }

  try {
    const response = await fetch('/api/stats', {cache: 'no-store'});
    if (!response.ok) throw new Error('Stats endpoint returned ' + response.status);
    const data = await response.json();
    setText('stat-total', data.total ?? 0);
    setText('stat-risk', data.high_risk ?? 0);
    setText('stat-average', data.average ?? 0);

    const hasScans = Number(data.total) > 0;
    showEmpty('trend-empty', !hasScans);
    showEmpty('risk-empty', !hasScans);
    showEmpty('category-empty', !((data.categories?.values || []).some(v => Number(v) > 0)));

    if (typeof Chart === 'undefined') {
      showChartError();
    }

    const palette = {Low:'#45d6b4', Medium:'#f5bd58', High:'#ff8a65', Critical:'#fa5478'};
    const grid = '#263247', muted = '#8290a8';
    const commonPlugins = {
      legend: {display:false},
      tooltip: {backgroundColor:'#111a29',borderColor:'#2a3850',borderWidth:1,titleColor:'#fff',bodyColor:'#b7c3d7',padding:12}
    };

    const trend = document.getElementById('trendChart');
    if (trend && hasScans) {
      new Chart(trend, {
        type:'line',
        data:{labels:data.days.labels,datasets:[{
          label:'Scans',data:data.days.values,borderColor:'#6e8cff',
          backgroundColor:'rgba(110,140,255,.13)',fill:true,tension:.38,
          pointRadius:4,pointBackgroundColor:'#8ca5ff',pointHoverRadius:6
        }]},
        options:{responsive:true,maintainAspectRatio:false,interaction:{intersect:false,mode:'index'},
          plugins:commonPlugins,scales:{
            x:{grid:{display:false},ticks:{color:muted}},
            y:{beginAtZero:true,grid:{color:grid},ticks:{color:muted,precision:0}}
          }}
      });
    }

    const risk = document.getElementById('riskChart');
    const riskValues = Object.values(data.levels || {});
    if (risk && hasScans && riskValues.some(v => Number(v) > 0)) {
      new Chart(risk, {
        type:'doughnut',
        data:{labels:Object.keys(data.levels),datasets:[{
          data:riskValues,backgroundColor:Object.keys(data.levels).map(k=>palette[k] || '#7d8ca5'),
          borderColor:'#111925',borderWidth:5,hoverOffset:7
        }]},
        options:{responsive:true,maintainAspectRatio:false,cutout:'73%',
          plugins:{...commonPlugins,legend:{display:false}}}
      });
    }

    const cat = document.getElementById('categoryChart');
    if (cat && (data.categories?.values || []).some(v => Number(v) > 0)) {
      new Chart(cat, {
        type:'bar',
        data:{labels:data.categories.labels,datasets:[{
          label:'Detected signals',data:data.categories.values,
          backgroundColor:'rgba(104,157,255,.75)',borderRadius:6,barThickness:18
        }]},
        options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:commonPlugins,
          scales:{
            x:{beginAtZero:true,grid:{color:grid},ticks:{color:muted,precision:0}},
            y:{grid:{display:false},ticks:{color:muted}}
          }}
      });
    }
  } catch (error) {
    console.error('PhishGuard dashboard charts:', error);
    ['stat-total','stat-risk','stat-average'].forEach(id => {
      if (document.getElementById(id)?.textContent === '—') setText(id, '0');
    });
    showChartError();
  }

  // Persistent lesson attempts: selections/feedback survive navigation and reset only on explicit retake.
  const readStore = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
  const writeStore = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch {} };
  const pathParts = location.pathname.split('/').filter(Boolean);
  const socialLessonPage = pathParts[0] === 'social-awareness' && pathParts[1] === 'lesson';
  const lessonId = pathParts[pathParts.length - 1] || '0';
  const progressKey = socialLessonPage ? 'phishguard_social_lesson_progress' : 'phishguard_lesson_progress';
  const attemptKey = (socialLessonPage ? 'phishguard_social_lesson_attempt_' : 'phishguard_lesson_attempt_') + lessonId;
  const progressStore = readStore(progressKey, {});
  const xpKey = socialLessonPage ? 'phishguard_social_lesson_xp' : 'phishguard_lesson_xp';
  const cards = [...document.querySelectorAll('[data-lesson], [data-social-lesson]')];
  cards.forEach(card => {
    const id = card.dataset.lesson || card.dataset.socialLesson;
    const done = Boolean(progressStore[id]?.completed);
    card.classList.toggle('completed', done);
    const status = card.querySelector('.lesson-status');
    if (status) { status.textContent = done ? 'COMPLETED ✓' : 'NOT COMPLETED'; status.classList.toggle('completed', done); }
    const link = card.querySelector('.lesson-open');
    if (link && done) link.innerHTML = 'Review lesson <span>↗</span>';
  });
  const lessonTotal = document.querySelectorAll('[data-lesson]').length;
  const lessonDone = Object.values(readStore('phishguard_lesson_progress', {})).filter(v => v?.completed).length;
  setText('awareness-progress', lessonTotal ? Math.round(lessonDone / lessonTotal * 100) + '%' : '0%');
  const progressBar = document.getElementById('awareness-progress-bar');
  if (progressBar) progressBar.style.width = (lessonTotal ? lessonDone / lessonTotal * 100 : 0) + '%';
  setText('awareness-progress-caption', lessonDone + ' of ' + lessonTotal + ' lessons completed');
  setText('awareness-xp', Number(localStorage.getItem('phishguard_lesson_xp') || 0) + ' XP');

  const lessonQuestions = [...document.querySelectorAll('.lesson-question')];
  const submitLesson = document.getElementById('submit-lesson');
  const retakeLesson = document.getElementById('retake-lesson');
  const progressLabel = document.getElementById('lesson-check-progress');
  const finishMessage = document.getElementById('lesson-finish-message');
  let attempt = readStore(attemptKey, {answers:{}, submitted:false, score:null});
  const selectedAnswers = new Map(Object.entries(attempt.answers || {}).map(([k,v])=>[Number(k),Number(v)]));
  function paintAttempt() {
    lessonQuestions.forEach((question, qi) => {
      const selected = selectedAnswers.get(qi), correct = Number(question.dataset.correct);
      question.querySelectorAll('[data-option]').forEach(button => {
        const option = Number(button.dataset.option);
        button.classList.toggle('selected', selected === option);
        button.classList.remove('answer-correct','answer-wrong');
        if (attempt.submitted) {
          if (option === correct) button.classList.add('answer-correct');
          if (option === selected && option !== correct) button.classList.add('answer-wrong');
          button.disabled = true;
        } else button.disabled = false;
      });
      const feedback = question.querySelector('.lesson-answer-feedback');
      if (feedback) {
        if (attempt.submitted) {
          const isCorrect = selected === correct;
          feedback.textContent = isCorrect ? 'Correct. ' + question.querySelectorAll('[data-option]')[correct].textContent + ' is the safest answer.' : 'Review: ' + question.querySelectorAll('[data-option]')[correct].textContent + ' is the safest answer. Your selection is saved for review.';
          feedback.className = 'lesson-answer-feedback visible ' + (isCorrect?'good':'bad');
        } else { feedback.textContent=''; feedback.className='lesson-answer-feedback'; }
      }
    });
    if (progressLabel) progressLabel.textContent = attempt.submitted ? 'Submitted · ' + attempt.score + ' / ' + lessonQuestions.length + ' correct' : selectedAnswers.size + ' of ' + lessonQuestions.length + ' answered';
    if (submitLesson) { submitLesson.disabled = attempt.submitted || selectedAnswers.size !== lessonQuestions.length; submitLesson.hidden = attempt.submitted; }
    if (retakeLesson) retakeLesson.hidden = !attempt.submitted;
    if (finishMessage) finishMessage.textContent = attempt.submitted ? 'Submitted: ' + attempt.score + ' / ' + lessonQuestions.length + ' correct. Your answers and feedback are saved. Press Take Test Again only when you want to reset this attempt.' : '';
  }
  lessonQuestions.forEach((question, qi) => question.querySelectorAll('[data-option]').forEach(button => button.addEventListener('click', () => {
    if (attempt.submitted) return;
    selectedAnswers.set(qi, Number(button.dataset.option));
    attempt.answers = Object.fromEntries(selectedAnswers); writeStore(attemptKey, attempt); paintAttempt();
  })));
  if (submitLesson) submitLesson.addEventListener('click', () => {
    if (attempt.submitted || selectedAnswers.size !== lessonQuestions.length) return;
    let score = 0;
    lessonQuestions.forEach((question, qi) => { if (selectedAnswers.get(qi) === Number(question.dataset.correct)) score++; });
    attempt = {answers:Object.fromEntries(selectedAnswers),submitted:true,score,submittedAt:new Date().toISOString()};
    writeStore(attemptKey, attempt);
    const id = String(lessonId);
    const wasDone = Boolean(progressStore[id]?.completed);
    progressStore[id] = {completed:true,score,total:lessonQuestions.length,completedAt:attempt.submittedAt};
    writeStore(progressKey, progressStore);
    if (!wasDone) localStorage.setItem(xpKey, String(Number(localStorage.getItem(xpKey)||0)+20+score*5));
    paintAttempt();
  });
  if (retakeLesson) retakeLesson.addEventListener('click', () => {
    if (!confirm('Reset this quiz attempt? Your previous answers and feedback for this attempt will be cleared.')) return;
    selectedAnswers.clear(); attempt={answers:{},submitted:false,score:null}; writeStore(attemptKey,attempt); paintAttempt();
  });
  paintAttempt();

  // Completed status on the Social Engineering lesson catalog.
  if (document.querySelector('[data-social-lesson]')) {
    const doneStore=readStore('phishguard_social_lesson_progress',{});
    document.querySelectorAll('[data-social-lesson]').forEach(card=>{
      const id=card.dataset.socialLesson,done=Boolean(doneStore[id]?.completed);
      card.classList.toggle('completed',done);
      const status=document.getElementById('social-lesson-status-'+id);
      if(status){status.textContent=done?'COMPLETED ✓':'NOT COMPLETED';status.classList.toggle('completed',done);}
    });
  }

  // Case answers persist with feedback, so learners can revisit incorrect choices.
  const cases = [...document.querySelectorAll('.case-check')];
  let social = readStore('phishguard_social_record', {answers:[],xp:0});
  const correctAnswers = {
    1:'Open the known campus portal independently; urgency is a common pressure tactic.',
    2:'A Unicode character can visually imitate another character while producing a different domain string.',
    3:'Never disclose an OTP. End the call and contact support through a known route.',
    4:'Payment changes need independent callback verification and documented approval.',
    5:'Use the carrier’s official app or website rather than a message link.',
    6:'Do not connect unknown media; report it to authorized IT/security staff.'
  };
  const correctLabels = {
    1:'Check the account through a known portal',2:'A different character can visually imitate Latin “o”',
    3:'Keep it private and verify support independently',4:'Independent callback plus documented approval',
    5:'Use the carrier\'s official app or website',6:'Leave it disconnected and report it'
  };
  const historyBody = document.getElementById('answer-history-body');
  const escapeHtml = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const dailyCase = ((Math.floor(Date.now()/86400000)) % Math.max(1,cases.length)) + 1;
  const dailyLink = document.getElementById('daily-case-link');
  if(dailyLink){dailyLink.href='#case-'+dailyCase;dailyLink.textContent='Today’s case: '+(cases[dailyCase-1]?.closest('.case-study').querySelector('h3').textContent||'Security scenario')+' →';}
  const renderHistory = () => {
    if (!historyBody) return;
    if (!social.answers.length) { historyBody.innerHTML='<tr><td colspan="5" class="empty-cell">Your completed case answers will appear here.</td></tr>'; return; }
    historyBody.innerHTML = social.answers.slice().reverse().map(a => `<tr><td>${escapeHtml(new Date(a.date).toLocaleString())}</td><td>${escapeHtml(a.caseTitle)}</td><td>${escapeHtml(a.selected)}</td><td><span class="history-result ${a.correct?'good':'bad'}">${a.correct?'CORRECT':'REVIEW'}</span></td><td>${escapeHtml(a.feedback)}</tr>`).join('');
  };
  const updateSocialStats = () => {
    setText('social-xp', social.xp);
    const xpbar=document.getElementById('social-xp-bar'); if(xpbar) xpbar.style.width=Math.min(100,social.xp%100)+'%';
    const attempted=social.answers.length, correct=social.answers.filter(a=>a.correct).length;
    setText('social-score', attempted ? Math.round(correct/attempted*100)+'%' : '0%');
    setText('social-score-caption', correct+' correct · '+(attempted-correct)+' to review · '+attempted+' attempts');
    const badges=[attempted>=1,correct>=3, new Set(social.answers.map(a=>a.caseId)).size>=6,social.xp>=100];
    const badgeIds=['starter','scout','analyst','guardian'];
    const labelIds=['starter','scout','analyst','guardian'];
    let earned=0;
    badges.forEach((earnedBadge,i)=>{
      if(earnedBadge) earned++;
      const icon=document.getElementById('badge-'+badgeIds[i]); if(icon) icon.classList.toggle('earned',earnedBadge);
      const label=document.getElementById('badge-label-'+labelIds[i]); if(label) {label.textContent=earnedBadge?'UNLOCKED':'LOCKED';label.classList.toggle('unlocked',earnedBadge);}
    });
    setText('social-badge-count',earned+' / 4');
    const daily=document.getElementById('daily-status');
    if(daily && social.answers.some(a=>a.date.slice(0,10)===new Date().toISOString().slice(0,10))) daily.textContent='✓ Daily practice completed today';
  };
  cases.forEach(card=>{
    const caseId=Number(card.dataset.case);
    card.querySelectorAll('[data-answer]').forEach(button=>button.addEventListener('click',()=>{
      if(card.dataset.done) return;
      card.dataset.done='1';
      const safe=button.dataset.answer==='safe';
      button.classList.add(safe?'case-selected-safe':'case-selected-risk');
      const safeButton=card.querySelector('[data-answer="safe"]'); safeButton?.classList.add('case-correct');
      card.querySelectorAll('button').forEach(b=>b.disabled=true);
      const feedback=card.querySelector('.case-feedback');
      const detail=safe? 'Good decision. ' : 'That choice creates risk. ';
      feedback.textContent=detail+correctAnswers[caseId];
      feedback.className='case-feedback visible '+(safe?'good':'bad');
      const answer={
        caseId,caseTitle:card.closest('.case-study').querySelector('h3').textContent,
        selected:button.textContent,correct:safe,feedback:correctAnswers[caseId],
        date:new Date().toISOString()
      };
      social.answers.push(answer);
      social.xp+=safe?15:5; // wrong answers still earn a small learning-completion reward
      writeStore('phishguard_social_record',social);
      updateSocialStats();renderHistory();
    }));
  });
  // Unified Security Education dashboard + earned batch shelf.
  const educationCatalog = [
    {track:'phishing',id:1,course:'Email & phishing',batches:[['Batch 01','Phishing message anatomy','Learn sender checks, urgency signals, and the structure of deceptive messages.'],['Batch 02','Attachments & malicious links','Recognize risky files, hidden destinations, and safe reporting steps.']]},
    {track:'phishing',id:2,course:'Safe browsing',batches:[['Batch 03','URL inspection','Read hostnames, paths, redirects, and browser indicators carefully.'],['Batch 04','Unicode & deceptive domains','Understand homograph attacks and visually similar characters from other scripts.']]},
    {track:'phishing',id:3,course:'Passwords & identity',batches:[['Batch 05','Password hygiene','Use unique, strong credentials and a trusted password manager.'],['Batch 06','MFA & account recovery','Protect authentication factors and recover accounts through official channels.']]},
    {track:'phishing',id:4,course:'Device security',batches:[['Batch 07','Updates & patching','Reduce exposure by applying trusted security updates.'],['Batch 08','Safe downloads & apps','Check sources, permissions, and unexpected installation prompts.']]},
    {track:'phishing',id:5,course:'Data & privacy',batches:[['Batch 09','Personal data protection','Limit sensitive information and verify the recipient.'],['Batch 10','Safe sharing','Use appropriate access controls and secure sharing practices.']]},
    {track:'phishing',id:6,course:'Report & recover',batches:[['Batch 11','Report suspicious activity','Use official reporting routes and preserve useful evidence.'],['Batch 12','Incident response','Take prompt, safe steps after a suspected interaction or compromise.']]},
    {track:'social',id:1,course:'Phishing & Email Manipulation',batches:[['Batch 13','Phishing message manipulation','Recognize impersonation, pressure, and message-based traps.'],['Batch 14','QR, attachment & reply traps','Handle concealed destinations and unexpected files safely.']]},
    {track:'social',id:2,course:'Pretexting & Impersonation',batches:[['Batch 15','Fabricated pretexts','Identify invented stories used to make requests seem legitimate.'],['Batch 16','Authority & trust manipulation','Verify unusual requests even when they appear to come from authority.']]},
    {track:'social',id:3,course:'Vishing, Smishing & OTP Scams',batches:[['Batch 17','Voice phishing & OTP pressure','Keep codes private and verify callers independently.'],['Batch 18','Text-message lures','Avoid unexpected links and check alerts through official apps.']]},
    {track:'social',id:4,course:'Business Email & Payment Fraud',batches:[['Batch 19','Business email compromise','Spot unusual requests for money, files, secrecy, or access.'],['Batch 20','Invoice & bank-detail changes','Use independent callbacks and documented approval controls.']]},
    {track:'social',id:5,course:'Baiting, Tailgating & Physical Social Engineering',batches:[['Batch 21','Baiting & unknown media','Avoid connecting found devices or following curiosity-based lures.'],['Batch 22','Tailgating & access control','Protect restricted spaces and follow visitor verification procedures.']]}
  ];
  const phishingProgress = readStore('phishguard_lesson_progress',{});
  const socialProgress = readStore('phishguard_social_lesson_progress',{});
  const earnedCourses = educationCatalog.filter(c => (c.track==='phishing'?phishingProgress:socialProgress)[String(c.id)]?.completed);
  const earnedBatches = earnedCourses.flatMap(c=>c.batches.map(b=>({track:c.track,course:c.course,id:b[0],title:b[1],description:b[2]})));
  const courseCount=educationCatalog.length, completedCount=earnedCourses.length;
  const educationXP=Number(localStorage.getItem('phishguard_lesson_xp')||0)+Number(localStorage.getItem('phishguard_social_lesson_xp')||0)+Number(readStore('phishguard_social_record',{xp:0}).xp||0);
  setText('education-progress',Math.round(completedCount/courseCount*100)+'%');
  setText('education-progress-caption',completedCount+' of '+courseCount+' courses completed');
  const educationBar=document.getElementById('education-progress-bar');if(educationBar)educationBar.style.width=(completedCount/courseCount*100)+'%';
  setText('education-xp',educationXP+' XP');setText('education-completed',completedCount+' / '+courseCount);setText('education-batches',earnedBatches.length+' / '+educationCatalog.reduce((n,c)=>n+c.batches.length,0));
  const miniIcons=document.getElementById('education-course-icons');if(miniIcons){miniIcons.replaceChildren();earnedCourses.forEach(c=>{const icon=document.createElement('i');icon.title=c.course+' completed';icon.textContent='✓';miniIcons.append(icon);});if(!completedCount){const empty=document.createElement('span');empty.className='collection-empty';empty.textContent='No courses yet';miniIcons.append(empty);}}
  const popoverList=document.getElementById('education-batch-list');if(popoverList){popoverList.replaceChildren();if(!earnedBatches.length){const empty=document.createElement('span');empty.className='collection-empty';empty.textContent='Complete a lesson to collect your first batch.';popoverList.append(empty);}else earnedBatches.forEach(b=>{const item=document.createElement('span');item.className='collected-batch-mini';item.textContent=b.id+' · '+b.title;popoverList.append(item);});}
  setText('collection-count',earnedBatches.length);
  // Awareness Center's horizontal batch ribbon and completed-course history cards.
  const batchRibbon=document.getElementById('education-batch-scroll');
  if(batchRibbon){
    batchRibbon.replaceChildren();
    educationCatalog.forEach(course=>{
      const progress=(course.track==='phishing'?phishingProgress:socialProgress)[String(course.id)]||{};
      const claimed=Boolean(progress.completed);
      const destination=course.track==='phishing'?`/awareness/lesson/${course.id}`:`/social-awareness/lesson/${course.id}`;
      course.batches.forEach((batch,index)=>{
        const link=document.createElement('a');
        link.className='education-batch-pill '+(claimed?'claimed':'unclaimed');
        link.href=destination;link.title=(claimed?'Collected · ':'Not collected yet · ')+course.course+' — '+batch[1];
        link.setAttribute('aria-label',batch[0]+' '+batch[1]+', '+course.course+(claimed?', collected':', not yet collected'));
        const state=document.createElement('span');state.className='batch-pill-state';state.textContent=claimed?'✦':'◇';
        const id=document.createElement('small');id.textContent=batch[0];
        const title=document.createElement('strong');title.textContent=batch[1];
        const courseName=document.createElement('span');courseName.className='batch-pill-course';courseName.textContent=course.course;
        link.append(state,id,title,courseName);batchRibbon.append(link);
      });
    });
  }
  const completedRibbon=document.getElementById('education-completed-scroll');
  if(completedRibbon){
    completedRibbon.replaceChildren();
    if(!earnedCourses.length){
      const empty=document.createElement('div');empty.className='education-completed-empty';
      empty.textContent='Complete a lesson and submit its final quiz to see your course card here.';completedRibbon.append(empty);
    }else earnedCourses.forEach(course=>{
      const progress=(course.track==='phishing'?phishingProgress:socialProgress)[String(course.id)]||{};
      const total=Number(progress.total)||0,score=Number(progress.score)||0;
      const percent=total?Math.round(score/total*100):0;
      const courseXP=20+score*5;
      const destination=course.track==='phishing'?`/awareness/lesson/${course.id}`:`/social-awareness/lesson/${course.id}`;
      const card=document.createElement('a');card.className='education-completed-card';card.href=destination;
      const top=document.createElement('div');top.className='completed-card-top';
      const label=document.createElement('span');label.textContent=course.track==='phishing'?'PHISHING AWARENESS':'SOCIAL ENGINEERING';
      const check=document.createElement('span');check.className='completed-check';check.textContent='✓';top.append(label,check);
      const title=document.createElement('h3');title.textContent=course.course;
      const batch=document.createElement('p');batch.className='completed-card-batch';batch.textContent=course.batches.map(b=>b[0]).join(' · ');
      const metrics=document.createElement('div');metrics.className='completed-card-metrics';
      [[courseXP+' XP','REWARD'],[score+' / '+total,'QUIZ SCORE'],[percent+'%','RESULT']].forEach(([value,caption])=>{
        const metric=document.createElement('div');const strong=document.createElement('strong');strong.textContent=value;const small=document.createElement('small');small.textContent=caption;metric.append(strong,small);metrics.append(metric);
      });
      const bar=document.createElement('div');bar.className='completed-result-bar';const fill=document.createElement('i');fill.style.width=percent+'%';bar.append(fill);
      card.append(top,title,batch,metrics,bar);completedRibbon.append(card);
    });
  }
  const shelf=document.getElementById('collected-batch-shelf');if(shelf){shelf.replaceChildren();if(!earnedBatches.length){const empty=document.createElement('div');empty.className='collection-empty-state';empty.innerHTML='<span>▤</span><h2>Your shelf is waiting</h2><p>Complete a phishing or social engineering lesson to collect its batch. Your earned batches will appear here.</p><a class="primary-btn" href="/phishing-awareness">Start learning <span>→</span></a>';shelf.append(empty);}else earnedBatches.forEach(batch=>{const tile=document.createElement('article');tile.className='collected-batch-tile';tile.tabIndex=0;const stamp=document.createElement('span');stamp.className='batch-stamp';stamp.textContent=batch.track==='phishing'?'PHISHING AWARENESS':'SOCIAL ENGINEERING';const title=document.createElement('h3');title.textContent=batch.id+' · '+batch.title;const summary=document.createElement('p');summary.textContent='Earned by completing: '+batch.course;const tip=document.createElement('span');tip.className='batch-hover-note';tip.textContent=batch.description;tile.append(stamp,title,summary,tip);shelf.append(tile);});}

  renderHistory();updateSocialStats();
  const clearHistory=document.getElementById('clear-answer-history');
  if(clearHistory) clearHistory.addEventListener('click',()=>{
    if(!confirm('Clear the saved case-answer history and social learning score from this browser?')) return;
    social={answers:[],xp:0};writeStore('phishguard_social_record',social);
    cases.forEach(card=>{delete card.dataset.done;card.querySelectorAll('button').forEach(b=>{b.disabled=false;b.classList.remove('case-selected-safe','case-selected-risk','case-correct')});const f=card.querySelector('.case-feedback');if(f){f.textContent='';f.className='case-feedback';}});
    renderHistory();updateSocialStats();
  });
});
