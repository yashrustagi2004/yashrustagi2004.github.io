---
layout: page
title: Projects
icon: fa-solid fa-diagram-project
order: 2
---

<style>
.projects-container {
  margin: 2rem 0;
}

.project-card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
  transition: all 0.3s ease;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.project-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  border-color: var(--link-color);
}

.project-title {
  margin: 0 0 0.5rem 0;
  font-size: 1.25rem;
  font-weight: 600;
}

.project-title a {
  text-decoration: none;
  color: var(--heading-color);
  transition: color 0.3s ease;
}

.project-title a:hover {
  color: var(--link-color);
}

.project-date {
  font-size: 0.9rem;
  color: var(--text-muted);
  font-style: italic;
  margin-bottom: 0.75rem;
}

.project-description {
  color: var(--text-color);
  line-height: 1.6;
}

.projects-header {
  text-align: center;
  margin-bottom: 2.5rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid var(--border-color);
}

.projects-subtitle {
  color: var(--text-muted);
  font-size: 1.1rem;
  margin-top: 0.5rem;
}

.no-projects {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-muted);
  font-style: italic;
}

.project-icon {
  margin-right: 0.5rem;
  color: var(--link-color);
}
</style>

<div class="projects-header">
  <h1><i class="fa-solid fa-diagram-project project-icon"></i>Projects</h1>
  <p class="projects-subtitle">A showcase of my technical projects and development work</p>
</div>

<div class="projects-container">
  {% assign project_posts = site.posts | where_exp: "post", "post.tags contains 'Projects'" %}
  
  {% if project_posts.size > 0 %}
    {% for post in project_posts %}
      <div class="project-card">
        <h3 class="project-title">
          <a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a>
        </h3>
        <div class="project-date">
          <i class="far fa-calendar-alt"></i> {{ post.date | date: "%B %d, %Y" }}
        </div>
        {% if post.description %}
          <div class="project-description">{{ post.description }}</div>
        {% endif %}
      </div>
    {% endfor %}
  {% else %}
    <div class="no-projects">
      <i class="fas fa-code fa-3x" style="margin-bottom: 1rem; opacity: 0.3;"></i>
      <p>No projects available yet. Check back soon for exciting new developments!</p>
    </div>
  {% endif %}
</div>

