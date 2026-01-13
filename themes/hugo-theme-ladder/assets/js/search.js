document.addEventListener('DOMContentLoaded', () => {
    const searchBtn = document.getElementById('search-btn');
    const searchModal = document.getElementById('search-modal');
    const searchClose = document.getElementById('search-close');
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    const searchClear = document.getElementById('search-clear');
    
    let fuse;
    let data = [];

    // Initialize Search
    async function initSearch() {
        try {
            const response = await fetch('/index.json');
            data = await response.json();
            
            const options = {
                keys: ['title', 'tags', 'categories', 'content'],
                threshold: 0.3, // 0.0 requires perfect match, 1.0 matches anything
                ignoreLocation: true,
                includeMatches: true,
                minMatchCharLength: 2
            };
            
            fuse = new Fuse(data, options);
        } catch (error) {
            console.error('Error fetching search index:', error);
        }
    }

    // Open Modal
    if (searchBtn) {
        searchBtn.addEventListener('click', (e) => {
            e.preventDefault();
            searchModal.style.display = 'flex'; // Explicitly set display
            // Small timeout to allow display change to register before adding class for animation (if needed)
            requestAnimationFrame(() => {
                searchModal.classList.add('active');
            });
            if (!fuse) initSearch();
            if (searchInput) {
                searchInput.focus();
                if (searchClear) {
                    searchClear.classList.toggle('visible', searchInput.value.trim().length > 0);
                }
            }
            document.body.style.overflow = 'hidden';
        });
    }

    // Close Modal
    if (searchClose) {
        searchClose.addEventListener('click', () => {
            closeModal();
        });
    }

    window.addEventListener('click', (e) => {
        if (e.target === searchModal) {
            closeModal();
        }
    });
    
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && (searchModal.classList.contains('active') || searchModal.style.display === 'flex')) {
            closeModal();
        }
    });

    function closeModal() {
        searchModal.classList.remove('active');
        setTimeout(() => {
             searchModal.style.display = 'none';
        }, 200);
        document.body.style.overflow = '';
        if (searchInput) {
            searchInput.value = '';
        }
        if (searchResults) {
            searchResults.innerHTML = '';
        }
        if (searchClear) {
            searchClear.classList.remove('visible');
        }
    }

    // Search Input
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            if (searchClear) {
                searchClear.classList.toggle('visible', e.target.value.trim().length > 0);
            }
            if (!fuse) return;
            
            const query = e.target.value.trim();
            if (query.length === 0) {
                if (searchResults) {
                    searchResults.innerHTML = '';
                }
                return;
            }

            const results = fuse.search(query);
            renderResults(results);
        });
    }

    if (searchClear && searchInput) {
        searchClear.addEventListener('click', () => {
            searchInput.value = '';
            searchInput.focus();
            if (searchResults) {
                searchResults.innerHTML = '';
            }
            searchClear.classList.remove('visible');
        });
    }

    function renderResults(results) {
        if (results.length === 0) {
            searchResults.innerHTML = '<div class="search-item">No results found</div>';
            return;
        }

        const html = results.map(result => {
            const item = result.item;
            const date = new Date(item.date).toLocaleDateString();
            
            // Highlight Title
            let title = item.title;
            const titleMatch = result.matches && result.matches.find(m => m.key === 'title');
            if (titleMatch) {
                title = highlightText(item.title, titleMatch.indices);
            }

            // Highlight Content Snippet
            let content = item.content ? item.content.substring(0, 150) + '...' : '';
            const contentMatch = result.matches && result.matches.find(m => m.key === 'content');
            if (contentMatch && item.content) {
                const firstIndex = contentMatch.indices[0][0];
                const start = Math.max(0, firstIndex - 75);
                const end = Math.min(item.content.length, firstIndex + 75);
                content = (start > 0 ? '...' : '') + 
                          highlightText(item.content.substring(start, end), adjustIndices(contentMatch.indices, start)) + 
                          (end < item.content.length ? '...' : '');
            }

            return `
                <div class="search-item">
                    <a href="${item.permalink}">
                        <div class="search-item-title">${title}</div>
                        <div class="search-item-meta">
                            <span>${date}</span>
                            ${item.tags ? ` · ${item.tags.join(', ')}` : ''}
                        </div>
                        <div class="search-item-desc">
                            ${content}
                        </div>
                    </a>
                </div>
            `;
        }).join('');

        searchResults.innerHTML = html;
    }

    function highlightText(text, indices) {
        let content = '';
        let lastIndex = 0;
        indices.forEach((range) => {
            if (range[0] >= text.length) return;
            const end = Math.min(range[1], text.length - 1);
            content += text.substring(lastIndex, range[0]);
            content += '<mark>' + text.substring(range[0], end + 1) + '</mark>';
            lastIndex = end + 1;
        });
        content += text.substring(lastIndex);
        return content;
    }

    function adjustIndices(indices, offset) {
        return indices
            .map(range => [range[0] - offset, range[1] - offset])
            .filter(range => range[0] >= 0 && range[1] >= 0); // Simple filter, could be better
    }
});
