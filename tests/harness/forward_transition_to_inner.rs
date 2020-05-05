#[macro_export]
macro_rules! forward_transition_to_inner {
    ($self: ty, $inner:ty) => {
        impl<M> Transition<M> for $self
        where
            $inner: Transition<M>,
        {
            fn transition(self, message: M, rng: &mut impl Rng) -> anyhow::Result<Self> {
                Ok(Self {
                    inner: Transition::transition(self.inner, message, rng)?,
                    ..self
                })
            }
        }
    };
}
