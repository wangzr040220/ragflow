-- PolyU Extension: Add fields to knowledgebase table
-- Run this migration after deploying RAGFlow with the updated db_models.py

-- Add subject category for knowledge base classification
ALTER TABLE knowledgebase ADD COLUMN IF NOT EXISTS subject_category VARCHAR(100);
CREATE INDEX IF NOT EXISTS idx_knowledgebase_subject_category ON knowledgebase(subject_category);

-- Add course code for linking knowledge bases to courses
ALTER TABLE knowledgebase ADD COLUMN IF NOT EXISTS course_code VARCHAR(50);
CREATE INDEX IF NOT EXISTS idx_knowledgebase_course_code ON knowledgebase(course_code);

-- Add department code for department-level filtering
ALTER TABLE knowledgebase ADD COLUMN IF NOT EXISTS dept_code VARCHAR(50);
CREATE INDEX IF NOT EXISTS idx_knowledgebase_dept_code ON knowledgebase(dept_code);

-- Add visibility control (private|department|public)
ALTER TABLE knowledgebase ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private';
CREATE INDEX IF NOT EXISTS idx_knowledgebase_visibility ON knowledgebase(visibility);

-- Add owner ID for PolyU user association
ALTER TABLE knowledgebase ADD COLUMN IF NOT EXISTS owner_id VARCHAR(100);
CREATE INDEX IF NOT EXISTS idx_knowledgebase_owner_id ON knowledgebase(owner_id);
