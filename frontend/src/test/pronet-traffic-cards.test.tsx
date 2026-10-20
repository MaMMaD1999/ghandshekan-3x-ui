import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import ProNetTrafficCards from '../components/ProNetTrafficCards';

vi.mock('react-i18next', () => ({ useTranslation: () => ({ i18n: { language: 'en' } }) }));

describe('subscription traffic visibility', () => {
  it('filters by billed bytes while retaining the exact threshold and separate rates', () => {
    const rows = [
      { inboundName: 'Unused', billedDown: 0, rawDown: 0 },
      { inboundName: 'Tiny charged', billedDown: 10 * 1024 * 1024 - 1, rawDown: 100 * 1024 * 1024 },
      { inboundName: 'Visible charged', billedDown: 10 * 1024 * 1024, rawDown: 5 * 1024 * 1024 },
    ].map((row, i) => ({ originGuid: '', inboundTag: `in-${i}`, email: 'subscriber', rateParts: 2000000, rawUp: 0, billedUp: 0, ...row }));
    render(<ProNetTrafficCards rows={rows} history />);
    expect(screen.queryByText('Unused')).toBeNull();
    expect(screen.queryByText('Tiny charged')).toBeNull();
    expect(screen.getByText('Visible charged')).toBeTruthy();
  });
});
