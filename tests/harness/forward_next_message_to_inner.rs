#[macro_export]
macro_rules! forward_next_message_to_inner {
    ($self: ty, $inner:ty) => {
        impl<M> crate::harness::NextMessage<M> for $self
        where
            $inner: crate::harness::NextMessage<M>,
        {
            fn next_message(&self, rng: &mut impl Rng) -> Result<M, NoMessage> {
                crate::harness::NextMessage::next_message(&self.inner, rng)
            }
        }
    };
}
