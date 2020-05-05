#[macro_export]
macro_rules! forward_next_message_to_inner {
    ($self: ty, $inner:ty) => {
        impl<M> NextMessage<M> for $self
        where
            $inner: NextMessage<M>,
        {
            fn next_message(&self, rng: &mut impl Rng) -> Result<M, NoMessage> {
                NextMessage::next_message(&self.inner, rng)
            }
        }
    };
}
