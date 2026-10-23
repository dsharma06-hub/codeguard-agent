import { Router } from 'express';
import { getSessionFromRequest, destroySession } from '../services/authService.js';

const router = Router();

/**
 * @route   GET /api/github/repos
 * @desc    Lists the authenticated user's GitHub repositories (both public and private)
 * @access  Private (requires valid GitHub OAuth session)
 */
router.get('/api/github/repos', async (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({
      error: 'Unauthorized. Please sign in with GitHub to view your repositories.',
    });
  }

  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(req.query.per_page, 10) || 30));
  const sort = typeof req.query.sort === 'string' ? req.query.sort : 'updated';
  const direction = typeof req.query.direction === 'string' ? req.query.direction : 'desc';
  const type = typeof req.query.type === 'string' ? req.query.type : 'all';

  try {
    const url = new URL('https://api.github.com/user/repos');
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    url.searchParams.set('sort', sort);
    url.searchParams.set('direction', direction);
    url.searchParams.set('type', type);

    const ghRes = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'CodeGuard-Scanner',
      },
    });

    if (!ghRes.ok) {
      if (ghRes.status === 401) {
        destroySession(session.sessionId);
        return res.status(401).json({
          error: 'GitHub session expired or token was revoked. Please log in again.',
        });
      }

      const errText = await ghRes.text();
      return res.status(ghRes.status).json({
        error: `GitHub API error (${ghRes.status}): ${errText}`,
      });
    }

    const repos = await ghRes.json();
    if (!Array.isArray(repos)) {
      return res.status(200).json([]);
    }

    const mappedRepos = repos.map((repo) => ({
      name: repo.name,
      full_name: repo.full_name,
      private: Boolean(repo.private),
      description: repo.description || '',
      default_branch: repo.default_branch || 'main',
      html_url: repo.html_url,
      updated_at: repo.updated_at,
    }));

    res.setHeader('X-Page', String(page));
    res.setHeader('X-Per-Page', String(perPage));
    return res.status(200).json(mappedRepos);
  } catch (err) {
    console.error('Failed to fetch repositories from GitHub API:', err);
    return res.status(500).json({
      error: 'An unexpected internal error occurred while fetching repositories from GitHub.',
    });
  }
});

export default router;
