---
layout: page
title: CTF Writeups
icon: fas fa-flag
order: 2
---

<style>
.ctf-container {
  margin: 2rem 0;
}

.ctf-card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  transition: all 0.3s ease;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  position: relative;
}

.ctf-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  border-color: #dc3545;
}

.ctf-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 4px;
  height: 100%;
  background: linear-gradient(135deg, #dc3545, #ff6b7a);
  border-radius: 8px 0 0 8px;
}

.ctf-title {
  margin: 0 0 0.5rem 0;
  font-size: 1.25rem;
  font-weight: 600;
}

.ctf-title a {
  text-decoration: none;
  color: var(--heading-color);
  transition: color 0.3s ease;
}

.ctf-title a:hover {
  color: #dc3545;
}

.ctf-date {
  font-size: 0.9rem;
  color: var(--text-muted);
  font-style: italic;
  margin-bottom: 0.75rem;
}

.ctf-description {
  color: var(--text-color);
  line-height: 1.6;
}

.ctf-header {
  text-align: center;
  margin-bottom: 2.5rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid var(--border-color);
}

.ctf-subtitle {
  color: var(--text-muted);
  font-size: 1.1rem;
  margin-top: 0.5rem;
}

.no-ctfs {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-muted);
  font-style: italic;
}

.ctf-icon {
  margin-right: 0.5rem;
  color: #dc3545;
}

.security-badge {
  display: inline-block;
  background: linear-gradient(135deg, #dc3545, #c82333);
  color: white;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 500;
  margin-left: 0.5rem;
  box-shadow: 0 2px 4px rgba(220, 53, 69, 0.3);
}

.challenge-type {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin-left: 1rem;
}
</style>

<div class="ctf-header">
  <h1><i class="fas fa-flag ctf-icon"></i>CTF Writeups</h1>
  <p class="ctf-subtitle">Capture The Flag challenge solutions and cybersecurity adventures</p>
</div>

<div class="ctf-container">
  {% assign ctf_posts = site.posts | where_exp: "post", "post.tags contains 'Writeups'" %}
  
  {% if ctf_posts.size > 0 %}
    {% for post in ctf_posts %}
      <div class="ctf-card">
        <h3 class="ctf-title">
          <a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a>
          <span class="security-badge">CTF</span>
        </h3>
        <div class="ctf-date">
          <i class="far fa-calendar-alt"></i> {{ post.date | date: "%B %d, %Y" }}
          {% if post.difficulty %}
            <span class="challenge-type">
              <i class="fas fa-layer-group"></i> {{ post.difficulty }}
            </span>
          {% endif %}
        </div>
        {% if post.description %}
          <div class="ctf-description">{{ post.description }}</div>
        {% endif %}
      </div>
    {% endfor %}
  {% else %}
    <div class="no-ctfs">
      <i class="fas fa-shield-alt fa-3x" style="margin-bottom: 1rem; opacity: 0.3; color: #dc3545;"></i>
      <p>No CTF writeups available yet. Check back soon for cybersecurity challenges and solutions!</p>
    </div>
  {% endif %}
</div>