(function(){
  const $ = (id)=>document.getElementById(id);
  const ips=$("ips"), domains=$("domains"), urls=$("urls"), hashes=$("hashes");
  const conf=$("confidence"), sev=$("severity"), prod=$("product"), prodCustom=$("productCustom"), comment=$("comment");
  const namePrefix=$("namePrefix"), nameMode=$("nameMode"), dedup=$("dedup");
  const preview=$("preview"), gen=$("gen"), copyBtn=$("copy"), dl=$("download"), openBtn=$("open"), demo=$("demo"), warn=$("warn");

  // ✅ Regex correctos (sin doble backslash)
  const ipRe = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const sha256Re = /\b[a-f0-9]{64}\b/gi;
  const md5Re = /\b[a-f0-9]{32}\b/gi;
  const urlRe = /\bhttps?:\/\/[^\s<>()"']+\b/gi;
  const domainRe = /\b(?=.{1,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;

  prod.addEventListener("change",()=>{ prodCustom.classList.toggle("hidden", prod.value!=="custom"); });

  // ✅ Split por salto de línea real \n (no "\\n")
  function normalizeLines(text){
    return (text||"").replace(/\r/g,"").split("\n").map(s=>s.trim()).filter(Boolean);
  }
  function hashCode(str){ let h=0; for(let i=0;i<str.length;i++){ h=((h<<5)-h)+str.charCodeAt(i); h|=0;} if(h<0) h = 0xFFFFFFFF + h + 1; return h.toString(36); }
  function csvEscape(s){ return `"${String(s).replace(/"/g,'""')}"`; }

  function parseIPs(){ return normalizeLines(ips.value).flatMap(line => (line.match(ipRe)||[])); }
  function parseURLs(){ return normalizeLines(urls.value).flatMap(line => (line.match(urlRe)||[])); }
  function parseHashes(){
    const out=[];
    normalizeLines(hashes.value).forEach(line=>{
      (line.match(sha256Re)||[]).forEach(h=>out.push(["SHA256", h.toLowerCase()]));
      (line.match(md5Re)||[]).forEach(h=>out.push(["MD5", h.toLowerCase()]));
    });
    return out;
  }
  function parseDomains(){
    let ds = normalizeLines(domains.value).flatMap(line => (line.match(domainRe)||[]).map(d=>d.toLowerCase()));
    const urlDomains = new Set(parseURLs().map(u=>u.replace(/^https?:\/\//i,"").split("/")[0].toLowerCase()));
    ds = ds.filter(d => !urlDomains.has(d));
    return ds;
  }

  function updateCounters(){
    $("ipsCount").textContent = parseIPs().length+" IPs";
    $("domainsCount").textContent = parseDomains().length+" dominios";
    $("urlsCount").textContent = parseURLs().length+" URLs";
    $("hashesCount").textContent = parseHashes().length+" hashes";
  }
  [ips,domains,urls,hashes].forEach(el=>el.addEventListener("input", updateCounters));
  updateCounters();

  function enableActions(ok){
    copyBtn.disabled = !ok; dl.disabled = !ok; openBtn.disabled = !ok;
  }

  function generate(){
    try{
      warn.textContent="";
      const C=(conf.value||"medium").toLowerCase();
      const S=(sev.value||"medium").toLowerCase();
      const P=(prod.value==="custom" ? (prodCustom.value||"CUSTOM") : (prod.value||"AV")).toUpperCase();
      const CM=comment.value||new Date().toISOString().slice(0,10);

      let data=[];
      parseIPs().forEach(v=>data.push(["IP",v]));
      parseURLs().forEach(v=>data.push(["URL",v]));
      parseDomains().forEach(v=>data.push(["DOMAIN",v]));
      parseHashes().forEach(([t,v])=>data.push([t,v]));

      if(data.length===0){
        warn.textContent="No hay datos. Ingresa al menos una IP/URL/dominio/hash.";
        preview.value=""; enableActions(false); $("rowsCount").textContent="0 filas";
        return;
      }

      if(dedup.value==="yes"){
        const seen=new Set();
        data=data.filter(([t,v])=>{const k=t+"|"+v.toLowerCase(); if(seen.has(k)) return false; seen.add(k); return true;});
      }

      const rows=[["UNIQ-NAME","VALUE","TYPE","CONFIDENCE","SEVERITY","PRODUCT","COMMENT"]];
      let idx=1;
      data.forEach(([type,value])=>{
        const name=(nameMode.value==="hash")?`${(namePrefix.value||"observ")}_${type.toLowerCase()}_${hashCode(value)}`:`${namePrefix.value||"observ"}${idx++}`;
        rows.push([name,value,type,C,S,P,CM]);
      });

      const csv=rows.map(r=>r.map(csvEscape).join(",")).join("\n");
      preview.value=csv;
      $("rowsCount").textContent=(rows.length-1)+" filas";
      enableActions(true);
    }catch(err){
      console.error(err);
      warn.textContent="Error generando CSV: "+(err && err.message ? err.message : err);
      enableActions(false);
    }
  }

  gen.addEventListener("click", generate);
  document.addEventListener("keydown",(e)=>{ if(e.ctrlKey && e.key==="Enter"){ generate(); }});

  copyBtn.addEventListener("click",()=>{
    if(!preview.value){ warn.textContent="Genera el CSV primero."; return; }
    preview.select(); document.execCommand("copy");
    copyBtn.textContent="¡Copiado!"; setTimeout(()=>copyBtn.textContent="Copiar",1200);
  });

  dl.addEventListener("click",()=>{
    if(!preview.value){ warn.textContent="Genera el CSV primero."; return; }
    try{
      const blob=new Blob([preview.value],{type:"text/csv;charset=utf-8"});
      const a=document.createElement("a");
      const ts=new Date().toISOString().slice(0,10).replace(/-/g,"");
      a.href=URL.createObjectURL(blob);
      a.download=`IOCs_${ts}.csv`;
      document.body.appendChild(a);
      a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href),4000);
      a.remove();
    }catch(err){
      console.error(err);
      warn.textContent="Descarga bloqueada por el navegador. Usa 'Abrir en pestaña'.";
    }
  });

  openBtn.addEventListener("click",()=>{
    if(!preview.value){ warn.textContent="Genera el CSV primero."; return; }
    const dataUri="data:text/csv;charset=utf-8,"+encodeURIComponent(preview.value);
    window.open(dataUri,"_blank");
  });

  demo.addEventListener("click",()=>{
    ips.value="83.150.218.93\n203.0.113.10";
    domains.value="malicioso.com\nphish-login.net";
    urls.value="http://malicioso.com/malware.exe\nhttps://phish-login.net/portal/index.html";
    hashes.value="d41d8cd98f00b204e9800998ecf8427e\na3c9d1f70c2bcb1fca92f19dbaf44b7d5e62d917708ea72b5e36d317f97dfc42";
    updateCounters();
  });
})();
