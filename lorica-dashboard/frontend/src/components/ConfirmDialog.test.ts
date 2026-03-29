import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import ConfirmDialog from './ConfirmDialog.svelte';

describe('ConfirmDialog', () => {
  const defaultProps = {
    title: 'Delete Item',
    message: 'Are you sure?',
    onconfirm: vi.fn(),
    oncancel: vi.fn(),
  };

  it('renders title and message', () => {
    render(ConfirmDialog, { props: defaultProps });
    expect(screen.getByText('Delete Item')).toBeInTheDocument();
    expect(screen.getByText('Are you sure?')).toBeInTheDocument();
  });

  it('renders default confirm label as Delete', () => {
    render(ConfirmDialog, { props: defaultProps });
    expect(screen.getByText('Delete')).toBeInTheDocument();
  });

  it('renders custom confirm label', () => {
    render(ConfirmDialog, { props: { ...defaultProps, confirmLabel: 'Remove' } });
    expect(screen.getByText('Remove')).toBeInTheDocument();
  });

  it('calls onconfirm when confirm button is clicked', async () => {
    const onconfirm = vi.fn();
    render(ConfirmDialog, { props: { ...defaultProps, onconfirm } });
    await fireEvent.click(screen.getByText('Delete'));
    expect(onconfirm).toHaveBeenCalledOnce();
  });

  it('calls oncancel when cancel button is clicked', async () => {
    const oncancel = vi.fn();
    render(ConfirmDialog, { props: { ...defaultProps, oncancel } });
    await fireEvent.click(screen.getByText('Cancel'));
    expect(oncancel).toHaveBeenCalledOnce();
  });

  it('calls oncancel when Escape key is pressed', async () => {
    const oncancel = vi.fn();
    render(ConfirmDialog, { props: { ...defaultProps, oncancel } });
    const overlay = screen.getByRole('dialog');
    await fireEvent.keyDown(overlay, { key: 'Escape' });
    expect(oncancel).toHaveBeenCalledOnce();
  });

  it('calls onconfirm when Enter key is pressed', async () => {
    const onconfirm = vi.fn();
    render(ConfirmDialog, { props: { ...defaultProps, onconfirm } });
    const overlay = screen.getByRole('dialog');
    await fireEvent.keyDown(overlay, { key: 'Enter' });
    expect(onconfirm).toHaveBeenCalledOnce();
  });
});
