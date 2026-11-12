INSERT INTO shadow_apps(name,vendor_name,domains,approved,category,vendor_score,risk_score,risk_level,last_seen) VALUES
('ChatGPT','OpenAI',ARRAY['chat.openai.com','chatgpt.com'],FALSE,'Generative AI',72,78,'High',NOW()-INTERVAL '8 minutes'),
('Notion AI','Notion Labs',ARRAY['notion.so'],TRUE,'Productivity AI',84,26,'Low',NOW()-INTERVAL '18 minutes'),
('Grammarly','Grammarly Inc.',ARRAY['grammarly.com'],TRUE,'Writing Assistant',88,18,'Low',NOW()-INTERVAL '32 minutes'),
('Claude','Anthropic',ARRAY['claude.ai'],FALSE,'Generative AI',80,64,'High',NOW()-INTERVAL '4 minutes'),
('Canva','Canva Pty Ltd',ARRAY['canva.com'],TRUE,'Design SaaS',86,22,'Low',NOW()-INTERVAL '1 hour'),
('DeepL','DeepL SE',ARRAY['deepl.com'],FALSE,'Translation AI',70,48,'Moderate',NOW()-INTERVAL '2 hours')
ON CONFLICT(name) DO NOTHING;
INSERT INTO incidents(app_id,title,severity,status,description,risk_score,detected_at)
SELECT id,'Confidential data transfer to unapproved AI service','Critical','Investigating','Synthetic proxy event indicates confidential data may have been sent to an unapproved AI application.',91,NOW()-INTERVAL '12 minutes'
FROM shadow_apps WHERE name='ChatGPT' AND NOT EXISTS(SELECT 1 FROM incidents WHERE title='Confidential data transfer to unapproved AI service');
INSERT INTO incidents(app_id,title,severity,status,description,risk_score,detected_at)
SELECT id,'Unapproved AI application detected','High','Open','Application observed in engineering department and requires vendor assessment.',68,NOW()-INTERVAL '48 minutes'
FROM shadow_apps WHERE name='Claude' AND NOT EXISTS(SELECT 1 FROM incidents WHERE title='Unapproved AI application detected');
INSERT INTO remediation_logs(incident_id,action,approved_by,status)
SELECT id,'Request application owner review and validate data handling controls','soc.analyst','Pending approval'
FROM incidents WHERE title='Unapproved AI application detected'
AND NOT EXISTS(SELECT 1 FROM remediation_logs WHERE action='Request application owner review and validate data handling controls');
INSERT INTO telemetry_events(app_id,domain,user_id,department,event_type,data_sensitivity,bytes_out,occurred_at,source,risk_score)
SELECT id,'chat.openai.com','u-1042','Engineering','data_transfer','confidential',24000000,NOW()-INTERVAL '12 minutes','synthetic-proxy',91 FROM shadow_apps WHERE name='ChatGPT';
