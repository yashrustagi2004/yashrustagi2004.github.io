---
layout: page
title: CTF Writeups
icon: fas fa-flag
order: 2
---

{% include lang.html %}

{% assign all_pinned = '' | split: '' %}
{% assign all_normal = '' | split: '' %}

{% for post in site.posts %}
  {% if post.tags contains "Writeups" %}
    {% if post.pin %}
      {% assign all_pinned = all_pinned | push: post %}
    {% elsif post.hidden != true %}
      {% assign all_normal = all_normal | push: post %}
    {% endif %}
  {% endif %}
{% endfor %}

{% assign posts = all_pinned | concat: all_normal %}

<div id="post-list" class="flex-grow-1 px-xl-1">
  {% for post in posts %}
    <article class="card-wrapper card">
      <a href="{{ post.url | relative_url }}" class="post-preview row g-0 flex-md-row-reverse">
        {% assign card_body_col = '12' %}

        {% if post.image %}
          {% assign src = post.image.path | default: post.image %}
          {% capture src %}{% include media-url.html src=src subpath=post.media_subpath %}{% endcapture %}

          {% assign alt = post.image.alt | xml_escape | default: 'Preview Image' %}

          {% assign lqip = null %}

          {% if post.image.lqip %}
            {% capture lqip_url %}{% include media-url.html src=post.image.lqip subpath=post.media_subpath %}{% endcapture %}
            {% assign lqip = 'lqip="' | append: lqip_url | append: '"' %}
          {% endif %}

          <div class="col-md-5">
            <img src="{{ src }}" alt="{{ alt }}" {{ lqip }}>
          </div>

          {% assign card_body_col = '7' %}
        {% endif %}

        <div class="col-md-{{ card_body_col }}">
          <div class="card-body d-flex flex-column">
            <h1 class="card-title my-2 mt-md-0">{{ post.title }}</h1>

            {% if post.description %}
              <div class="card-text content mt-0 mb-3">
                <p>{{ post.description }}</p>
              </div>
            {% endif %}

            <div class="post-meta flex-grow-1 d-flex align-items-end">
              <div class="me-auto">
                <!-- posted date -->
                <i class="far fa-calendar fa-fw me-1"></i>
                {% include datetime.html date=post.date lang=lang %}

                <!-- categories -->
                {% if post.categories.size > 0 %}
                  <i class="far fa-folder-open fa-fw me-1"></i>
                  <span class="categories">
                    {% for category in post.categories %}
                      {{ category }}
                      {%- unless forloop.last -%},{%- endunless -%}
                    {% endfor %}
                  </span>
                {% endif %}
              </div>

              {% if post.pin %}
                <div class="pin ms-1">
                  <i class="fas fa-thumbtack fa-fw"></i>
                  <span>{{ site.data.locales[lang].post.pin_prompt }}</span>
                </div>
              {% endif %}
            </div>
            <!-- .post-meta -->
          </div>
          <!-- .card-body -->
        </div>
      </a>
    </article>
  {% endfor %}
</div>
<!-- #post-list -->