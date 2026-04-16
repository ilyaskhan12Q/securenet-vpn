-- Migration: 0003_seed_servers.sql
-- Seed VPN servers with 15 real, publicly reachable Cloudflare WARP endpoints.
-- Public Key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo= (CF WARP)

DELETE FROM servers;

INSERT INTO servers (id, name, country_code, city, endpoint, public_key, load_percent, features, online)
VALUES 
-- US
('11111111-1111-4111-8111-111111111101', 'US-NewYork-01', 'US', 'New York', '162.159.192.1:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 38, ARRAY['wireguard', 'no-logs'], TRUE),
('11111111-1111-4111-8111-111111111102', 'US-LosAngeles-01', 'US', 'Los Angeles', '162.159.195.1:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 51, ARRAY['wireguard', 'no-logs'], TRUE),
('11111111-1111-4111-8111-111111111103', 'US-Dallas-01', 'US', 'Dallas', '162.159.193.1:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 29, ARRAY['wireguard', 'no-logs'], TRUE),
-- CA
('55555555-5555-4555-8555-555555555501', 'CA-Toronto-01', 'CA', 'Toronto', '162.159.192.100:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 22, ARRAY['wireguard', 'no-logs'], TRUE),
-- UK
('22222222-2222-4222-8222-222222222201', 'UK-London-01', 'GB', 'London', '162.159.192.2:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 44, ARRAY['wireguard', 'no-logs'], TRUE),
-- DE
('33333333-3333-4333-8333-333333333301', 'DE-Frankfurt-01', 'DE', 'Frankfurt', '162.159.192.3:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 31, ARRAY['wireguard', 'no-logs'], TRUE),
-- NL
('33333333-3333-4333-8333-333333333302', 'NL-Amsterdam-01', 'NL', 'Amsterdam', '162.159.192.4:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 27, ARRAY['wireguard', 'no-logs', 'p2p'], TRUE),
-- FR
('33333333-3333-4333-8333-333333333303', 'FR-Paris-01', 'FR', 'Paris', '162.159.192.5:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 33, ARRAY['wireguard', 'no-logs'], TRUE),
-- CH
('33333333-3333-4333-8333-333333333304', 'CH-Zurich-01', 'CH', 'Zurich', '162.159.192.6:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 18, ARRAY['wireguard', 'no-logs', 'privacy-law'], TRUE),
-- SE
('33333333-3333-4333-8333-333333333305', 'SE-Stockholm-01', 'SE', 'Stockholm', '162.159.192.7:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 14, ARRAY['wireguard', 'no-logs'], TRUE),
-- NO
('33333333-3333-4333-8333-333333333306', 'NO-Oslo-01', 'NO', 'Oslo', '162.159.192.8:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 11, ARRAY['wireguard', 'no-logs'], TRUE),
-- SG
('44444444-4444-4444-8444-444444444401', 'SG-Singapore-01', 'SG', 'Singapore', '162.159.192.9:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 46, ARRAY['wireguard', 'no-logs', 'gaming-opt'], TRUE),
-- JP
('44444444-4444-4444-8444-444444444402', 'JP-Tokyo-01', 'JP', 'Tokyo', '162.159.192.10:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 39, ARRAY['wireguard', 'no-logs', 'gaming-opt'], TRUE),
-- AU
('44444444-4444-4444-8444-444444444403', 'AU-Sydney-01', 'AU', 'Sydney', '162.159.192.11:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 25, ARRAY['wireguard', 'no-logs'], TRUE),
-- BR
('55555555-5555-4555-8555-555555555502', 'BR-SaoPaulo-01', 'BR', 'São Paulo', '162.159.192.12:2408', 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 17, ARRAY['wireguard', 'no-logs'], TRUE)
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    country_code = EXCLUDED.country_code,
    city = EXCLUDED.city,
    endpoint = EXCLUDED.endpoint,
    public_key = EXCLUDED.public_key,
    load_percent = EXCLUDED.load_percent,
    features = EXCLUDED.features,
    online = EXCLUDED.online;