document.addEventListener("DOMContentLoaded",()=>{const i=document.getElementById("search-btn"),e=document.getElementById("search-modal"),a=document.getElementById("search-close"),n=document.getElementById("search-input"),s=document.getElementById("search-results");let t,r=[];async function c(){try{const e=await fetch("/index.json");r=await e.json();const n={keys:["title","tags","categories","content"],threshold:.3,ignoreLocation:!0};t=new Fuse(r,n)}catch(e){console.error("Error fetching search index:",e)}}i&&i.addEventListener("click",s=>{s.preventDefault(),e.classList.add("active"),t||c(),n.focus(),document.body.style.overflow="hidden"}),a&&a.addEventListener("click",()=>{o()}),window.addEventListener("click",t=>{t.target===e&&o()}),window.addEventListener("keydown",t=>{t.key==="Escape"&&e.classList.contains("active")&&o()});function o(){e.classList.remove("active"),document.body.style.overflow=""}n&&n.addEventListener("input",e=>{if(!t)return;const n=e.target.value.trim();if(n.length===0){s.innerHTML="";return}const o=t.search(n);l(o)});function l(e){if(e.length===0){s.innerHTML='<div class="search-item">No results found</div>';return}const t=e.map(e=>{const t=e.item,n=new Date(t.date).toLocaleDateString();return`
                <div class="search-item">
                    <a href="${t.permalink}">
                        <div class="search-item-title">${t.title}</div>
                        <div class="search-item-meta">
                            <span>${n}</span>
                            ${t.tags?` · ${t.tags.join(", ")}`:""}
                        </div>
                        <div class="search-item-desc">
                            ${t.content?t.content.substring(0,150)+"...":""}
                        </div>
                    </a>
                </div>
            `}).join("");s.innerHTML=t}})