CREATE TABLE IF NOT EXISTS kb_articles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL DEFAULT 'general',
  content TEXT NOT NULL,
  tags JSONB NOT NULL DEFAULT '[]',
  author_id UUID,
  view_count INT NOT NULL DEFAULT 0,
  helpful_count INT NOT NULL DEFAULT 0,
  not_helpful_count INT NOT NULL DEFAULT 0,
  published BOOL NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_kb_articles_slug ON kb_articles(slug);
CREATE INDEX IF NOT EXISTS idx_kb_articles_category ON kb_articles(category);
CREATE INDEX IF NOT EXISTS idx_kb_articles_published ON kb_articles(published);
CREATE INDEX IF NOT EXISTS idx_kb_articles_search ON kb_articles USING gin(to_tsvector('english', title || ' ' || content));
