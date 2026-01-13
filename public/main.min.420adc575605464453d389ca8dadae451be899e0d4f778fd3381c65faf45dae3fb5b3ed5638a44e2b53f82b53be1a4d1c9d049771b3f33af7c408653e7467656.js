document.addEventListener("DOMContentLoaded",()=>{const i=document.getElementById("search-btn"),e=document.getElementById("search-modal"),a=document.getElementById("search-close"),n=document.getElementById("search-input"),s=document.getElementById("search-results");let t,r=[];async function l(){try{const e=await fetch("/index.json");r=await e.json();const n={keys:["title","tags","categories","content"],threshold:.3,ignoreLocation:!0,includeMatches:!0,minMatchCharLength:2};t=new Fuse(r,n)}catch(e){console.error("Error fetching search index:",e)}}i&&i.addEventListener("click",s=>{s.preventDefault(),e.classList.add("active"),t||l(),n.focus(),document.body.style.overflow="hidden"}),a&&a.addEventListener("click",()=>{o()}),window.addEventListener("click",t=>{t.target===e&&o()}),window.addEventListener("keydown",t=>{t.key==="Escape"&&e.classList.contains("active")&&o()});function o(){e.classList.remove("active"),document.body.style.overflow=""}n&&n.addEventListener("input",e=>{if(!t)return;const n=e.target.value.trim();if(n.length===0){s.innerHTML="";return}const o=t.search(n);d(o)});function d(e){if(e.length===0){s.innerHTML='<div class="search-item">No results found</div>';return}const t=e.map(e=>{const t=e.item,a=new Date(t.date).toLocaleDateString();let s=t.title;const o=e.matches&&e.matches.find(e=>e.key==="title");o&&(s=c(t.title,o.indices));let i=t.content?t.content.substring(0,150)+"...":"";const n=e.matches&&e.matches.find(e=>e.key==="content");if(n&&t.content){const s=n.indices[0][0],e=Math.max(0,s-75),o=Math.min(t.content.length,s+75);i=(e>0?"...":"")+c(t.content.substring(e,o),u(n.indices,e))+(o<t.content.length?"...":"")}return`
                <div class="search-item">
                    <a href="${t.permalink}">
                        <div class="search-item-title">${s}</div>
                        <div class="search-item-meta">
                            <span>${a}</span>
                            ${t.tags?` · ${t.tags.join(", ")}`:""}
                        </div>
                        <div class="search-item-desc">
                            ${i}
                        </div>
                    </a>
                </div>
            `}).join("");s.innerHTML=t}function c(e,t){let n="",s=0;return t.forEach(t=>{if(t[0]>=e.length)return;const o=Math.min(t[1],e.length-1);n+=e.substring(s,t[0]),n+="<mark>"+e.substring(t[0],o+1)+"</mark>",s=o+1}),n+=e.substring(s),n}function u(e,t){return e.map(e=>[e[0]-t,e[1]-t]).filter(e=>e[0]>=0&&e[1]>=0)}})